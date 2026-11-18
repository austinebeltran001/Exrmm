# ============================================================================
# Ex Softwares RMM Agent - cleanup of a stuck / broken MSI registration
# ============================================================================
# Use this when the agent MSI cannot be uninstalled or re-installed
# (Windows Installer error 2762), e.g. because it was installed with the
# pre-2026-10-16 build whose service-removal custom action was sequenced
# outside the install script. Typical symptoms:
#   * "The installer has encountered an unexpected error installing this
#     package. The error code is 2762." during uninstall, or during the
#     "Preparing to remove older versions of this application..." step of
#     a reinstall.
#   * The product stays listed in "Apps & features" even after files were
#     deleted by hand.
#
# The script removes ONLY the Windows Installer registration of products
# whose display name starts with "Ex Softwares RMM Agent", the agent's
# Windows service, and the agent's leftovers. It never touches other
# products.
#
# Run in an ELEVATED PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\windows-cleanup-stuck-msi.ps1
#
# Afterwards install the fixed MSI (downloaded from the dashboard after
# 2026-10-16 02:16 UTC) - it will run as a clean first-time install.
# ============================================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

function Get-PackedGuid {
    # Windows Installer stores GUIDs "packed" (byte order reversed) in the
    # Installer registry hives. GUID {7D9A3C1E-4B52-4F6E-9E3A-1C2F5A8B7D40}
    # becomes 1E3C9A7D524B6E4FE9A3C1F2A5B8D704.
    param([Parameter(Mandatory = $true)][string]$Guid)
    $h = $Guid.Trim('{', '}').Replace('-', '')
    if ($h.Length -ne 32) { throw "not a GUID: $Guid" }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($n in 8, 4, 4) {
        for ($i = $n - 2; $i -ge 0; $i -= 2) {
            [void]$sb.Append($h.Substring($pos + $i, 2))
        }
        $pos += $n
    }
    for ($i = $pos; $i -lt 32; $i += 2) {
        [void]$sb.Append($h.Substring($i + 1, 1))
        [void]$sb.Append($h.Substring($i, 1))
    }
    $sb.ToString().ToUpper()
}

function Remove-Key([string]$Path) {
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host ("  removed key  {0}" -f $Path)
    }
}

function Remove-ValueNamed([string]$KeyPath, [string]$ValueName) {
    if (Test-Path $KeyPath) {
        $k = Get-Item -Path $KeyPath -ErrorAction SilentlyContinue
        if ($k -and $k.Property -contains $ValueName) {
            Remove-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
            Write-Host ("  removed value {0}  from  {1}" -f $ValueName, $KeyPath)
        }
    }
}

Write-Host ''
Write-Host '== 1. Stopping the agent service and processes ==' -ForegroundColor Cyan

Get-Process -Name 'ex-softwares-agent', 'ex-softwares-agent-svc' -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Host ("  stopping process  {0} (pid {1})" -f $_.ProcessName, $_.Id)
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }

# The MSI starts the agent with `-fullinstall`, which COPIES the binary to
# "%ProgramFiles%\Mesh Agent" and registers a service named "MeshAgent". That
# copy and service are the ones that actually run - the files under
# "%ProgramFiles%\ExSoftwares\Agent" are only the installer's source. If the
# folder was deleted by hand, the MeshAgent service survives pointing at a
# missing image and the next install aborts silently. Remove all three shapes:
#   * ex-softwares-agent* processes / services
#   * the MeshAgent service (whatever its ImagePath)
#   * any service still pointing into a \Mesh Agent\ or \ExSoftwares\Agent\ path
$svcPatterns = @('*ex-softwares-agent*.exe*', '*\Mesh Agent\*.exe*', '*\ExSoftwares\Agent\*.exe*')
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {
        $path = $_.PathName
        $_.Name -eq 'MeshAgent' -or ($path -and ($svcPatterns | Where-Object { $path -like $_ }))
    } |
    ForEach-Object {
        Write-Host ("  stopping service  {0}  ({1})" -f $_.Name, $_.PathName)
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        & sc.exe delete "$($_.Name)" | Out-Null
        Write-Host ("  deleted service   {0}" -f $_.Name)
    }

# The agent also drops a scheduled task for its own upkeep on some builds.
foreach ($task in @('MeshAgent', 'Ex Softwares Agent')) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host ("  removed scheduled task  {0}" -f $task)
    }
}

Write-Host ''
Write-Host '== 2. Finding stuck product registrations ==' -ForegroundColor Cyan

$roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$products = @()
foreach ($root in $roots) {
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DisplayName -like 'Ex Softwares RMM Agent*') {
            $products += [pscustomobject]@{
                DisplayName = $p.DisplayName
                ProductCode = $_.PSChildName
            }
        }
    }
}

if (-not $products) {
    Write-Host '  no "Ex Softwares RMM Agent" entry found in Apps & features - nothing to unregister.' -ForegroundColor Yellow
} else {
    foreach ($prod in $products) {
        $code = $prod.ProductCode
        if ($code -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') {
            Write-Host ("  skipping {0} - PSChildName is not a product code ({1})" -f $prod.DisplayName, $code) -ForegroundColor Yellow
            continue
        }
        Write-Host ''
        Write-Host ("== 3. Unregistering  {0}  ({1}) ==" -f $prod.DisplayName, $code) -ForegroundColor Cyan
        $packed = Get-PackedGuid $code

        # The per-product registration lives in four places. All four must go,
        # otherwise msiexec keeps treating the product as installed.
        Remove-Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$code"
        Remove-Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$code"
        Remove-Key "HKLM:\SOFTWARE\Classes\Installer\Products\$packed"
        Remove-Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$packed"

        # Upgrade-code cross references (any UpgradeCodes hive).
        foreach ($ucRoot in @(
                'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes'
            )) {
            if (Test-Path $ucRoot) {
                Get-ChildItem $ucRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-ValueNamed $_.PSPath $packed
                }
            }
        }

        # Component cross references: every component this product installed.
        foreach ($compRoot in @(
                'HKLM:\SOFTWARE\Classes\Installer\Components',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components'
            )) {
            if (Test-Path $compRoot) {
                Get-ChildItem $compRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-ValueNamed $_.PSPath $packed
                }
            }
        }
    }
}

Write-Host ''
Write-Host '== 4. Leftover agent data ==' -ForegroundColor Cyan
Remove-Key 'HKLM:\SOFTWARE\Ex Softwares LLC'
foreach ($dir in @("$env:ProgramFiles\ExSoftwares", "${env:ProgramFiles(x86)}\ExSoftwares", "$env:ProgramFiles\Mesh Agent", "${env:ProgramFiles(x86)}\Mesh Agent", "$env:ProgramData\ExSoftwares")) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host ("  removed folder  {0}" -f $dir)
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host 'If "Apps & features" still lists the agent, sign out and back in (or reboot) to refresh the list.'
Write-Host 'Now install the fixed MSI from the dashboard - it will behave like a clean first-time install.'
