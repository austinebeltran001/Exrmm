<#
.SYNOPSIS
    Verifies that an EX SOFTWARE LLC agent package (.msi or .exe, both from the
    portal) installs itself under its DEVICE GROUP name, and that the installed
    agent is registered as a running Windows service.

.DESCRIPTION
    Run this on the Windows test machine, elevated, after downloading a package
    from the portal for one group. It works for both download formats:

      * exagent-setup.msi  (Windows Installer, per machine)
      * exagent-setup.exe  (one-click NSIS installer, silent, one UAC prompt)

    Checks performed after a real install:

      * Add/Remove Programs shows the DEVICE GROUP NAME - not a generic agent
        name and not the downloaded file name
      * files land in "%ProgramFiles%\<group>\Agent"
      * the service is named per group, displays the group name, starts
        automatically and its binary path points at this group's own copy
      * the per-group registry metadata is complete (mesh id and server URL are
        exactly what the agent needs to enrol)
      * the installer's own log records a healthy service start
      * (optional) uninstall leaves no folder, service, registry key or
        Add/Remove Programs entry behind
      * (optional) a second group installs alongside without disturbing the first

    Because the group name is the only naming source, the same checks pass for
    a package whose file name says nothing about the group.

.PARAMETER PackagePath
    Path to the package downloaded from the portal for -Group (.msi or .exe).

.PARAMETER Group
    Device group name exactly as it appears in the portal.

.PARAMETER OtherGroup
    Optional second group used for the "two groups coexist" check.

.PARAMETER OtherPackagePath
    Optional package for -OtherGroup. When given it is installed before the
    main checks and must survive the main install and uninstall.

.PARAMETER Uninstall
    After the checks, uninstall the package and verify nothing is left behind.

.PARAMETER WorkDir
    Where logs and the report are written. Default: <systemdrive>\EXagent-install-test

.EXAMPLE
    .\verify-agent-installer.ps1 -PackagePath C:\Users\me\Downloads\exagent-setup.msi -Group Mercedes

.EXAMPLE
    .\verify-agent-installer.ps1 -PackagePath .\exagent-setup.exe -Group "Mercedes" -Uninstall

.EXAMPLE
    .\verify-agent-installer.ps1 -PackagePath .\exagent-setup.msi -Group Mercedes `
        -OtherGroup Exagent1999 -OtherPackagePath .\Exagent1999.msi -Uninstall

.NOTES
    ASCII-only and Windows PowerShell 5.1 compatible on purpose: that is the
    PowerShell every stock Windows 10/11 machine has.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('MsiPath', 'ExePath')]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [string]$Group,

    [string]$OtherGroup,

    [Alias('OtherMsiPath')]
    [string]$OtherPackagePath,

    [switch]$Uninstall,

    [string]$WorkDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $WorkDir) { $WorkDir = Join-Path $env:SystemDrive 'EXagent-install-test' }
if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}

$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Checks = New-Object System.Collections

function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $script:Checks.Add([pscustomobject]@{ Check = $Name; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
    if (-not $Ok) { $script:Failures.Add($Name + ': ' + $Detail) }
    $colour = 'Green'
    if (-not $Ok) { $colour = 'Red' }
    Write-Host ('[{0}] {1} - {2}' -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) -ForegroundColor $colour
}

function Add-Info {
    param([string]$Message)
    Write-Host ('       ' + $Message) -ForegroundColor DarkGray
}

# ------------------------------------------------------------- derivations ---
# These mirror scripts/build_msi.py and backend/src/builder.js exactly: the
# portal names every artefact from the device group name, so the test has to
# compute the same values from the same input.

function Get-InstalledDirName {
    param([string]$Client)
    $name = ($Client -replace '[<>:"/\\\|\?\*\x00-\x1f]', '-')
    $name = $name.Replace('$', '').Replace('%', '')
    $name = ($name -replace '\s+', ' ').Trim().Trim('.').Trim()
    if ($name.Length -gt 40) { $name = $name.Substring(0, 40).Trim().Trim('.').Trim() }
    if (-not $name) { $name = 'EXagent' }
    $reserved = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    if ($reserved -contains $name.Split('.')[0].ToUpperInvariant()) { $name = $name + '-agent' }
    return $name
}

function Get-ServiceNameFor {
    param([string]$Client)
    $key = ($Client.ToLowerInvariant() -replace '[^a-z0-9]', '')
    if (-not $key) {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Client))
        $key = (-join ($bytes | ForEach-Object { $_.ToString('x2') })).Substring(0, 12)
    }
    if ($key.Length -gt 40) { $key = $key.Substring(0, 40) }
    return 'ExSoftwaresAgent_' + $key
}

function Get-ArpEntry {
    param([string]$DisplayName)
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $found = @()
    foreach ($p in $paths) {
        $items = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        foreach ($i in $items) {
            if ($i.PSObject.Properties.Name -contains 'DisplayName' -and $i.DisplayName) {
                if ($i.DisplayName -eq $DisplayName) { $found += $i }
            }
        }
    }
    return $found
}

function Get-ServiceBinary {
    param([string]$Name)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($Name -replace "'", "''")) -ErrorAction SilentlyContinue
    if ($svc) { return $svc.PathName }
    return $null
}

function Get-PackageFormat {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.msi') { return 'msi' }
    if ($ext -eq '.exe') { return 'exe' }
    return 'unknown'
}

function Invoke-PackageInstall {
    param([string]$Path, [string]$LogPath, [string]$Format)
    if ($Format -eq 'msi') {
        $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('"' + $Path + '"'), '/qn', '/norestart', '/l*v', ('"' + $LogPath + '"')) -Wait -PassThru
        return $p.ExitCode
    }
    # The .exe is a silent NSIS installer: no /S needed for the pages, but /S
    # keeps it silent even if the compile-time flag were ever changed.
    $p = Start-Process -FilePath $Path -ArgumentList @('/S') -Wait -PassThru
    return $p.ExitCode
}

# ---------------------------------------------------------------- preflight ---
if (-not (Test-Path -LiteralPath $PackagePath)) {
    Write-Host ('Package not found: ' + $PackagePath) -ForegroundColor Red
    exit 2
}
$PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
$format = Get-PackageFormat -Path $PackagePath
if ($format -eq 'unknown') {
    Write-Host ('Unsupported package type (expected .msi or .exe): ' + $PackagePath) -ForegroundColor Red
    exit 2
}

$expectedDir = Get-InstalledDirName -Client $Group
$expectedService = Get-ServiceNameFor -Client $Group
$expectedFolder = Join-Path $env:ProgramFiles $expectedDir
$expectedInstallDir = Join-Path $expectedFolder 'Agent'
$expectedAgent = Join-Path $expectedInstallDir 'ex-softwares-agent.exe'
$expectedRunner = Join-Path $expectedInstallDir 'ex-softwares-agent-svc.exe'
$expectedHelper = Join-Path $expectedInstallDir 'agent-service.ps1'
$regPath = 'HKLM:\Software\EXagent\Groups\' + $expectedDir
$uninstKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\EXagent_' + $expectedDir
$installLog = Join-Path (Join-Path (Join-Path $env:ProgramData 'EXagent') $expectedDir) 'agent-install.log'

Write-Host ''
Write-Host ('EX SOFTWARE LLC agent package verification - group "{0}"' -f $Group) -ForegroundColor Cyan
Write-Host ('  host      : {0}' -f $env:COMPUTERNAME)
Write-Host ('  PowerShell: {0}' -f $PSVersionTable.PSVersion.ToString())
Write-Host ('  package   : {0} ({1})' -f $PackagePath, $format)
Write-Host ''
Add-Info ('expected install dir : ' + $expectedInstallDir)
Add-Info ('expected service     : ' + $expectedService)
Add-Info ('expected registry key: ' + $regPath)
Add-Info ('expected agent log   : ' + $installLog)

# Names that must NOT be produced any more: the download file name is generic,
# a generic product name would mean the group name never reached the package.
$genericNames = @('exagent-setup', 'EXagent', 'EXAGENT', 'ex-softwares-agent', 'exagent', 'Agent')

Write-Host ''
Write-Host '--- before install ---' -ForegroundColor Cyan
$beforeArp = Get-ArpEntry -DisplayName $Group
Add-Info ('Add/Remove Programs entries already present for this group: ' + $beforeArp.Count)
foreach ($entry in $beforeArp) {
    Add-Info ('  existing entry: "' + $entry.DisplayName + '" ' + $entry.PSChildName + ' ' + $entry.DisplayVersion)
}
foreach ($generic in $genericNames) {
    foreach ($entry in (Get-ArpEntry -DisplayName $generic)) {
        Add-Info ('  legacy/generic entry: "' + $entry.DisplayName + '" ' + $entry.PSChildName)
    }
}

if (-not $OtherGroup -and $OtherPackagePath) { $OtherGroup = $Group }
$otherDir = $null
$otherService = $null
if ($OtherGroup) {
    $otherDir = Join-Path $env:ProgramFiles (Get-InstalledDirName -Client $OtherGroup)
    $otherService = Get-ServiceNameFor -Client $OtherGroup
    if ($OtherPackagePath) {
        Write-Host ''
        Write-Host ('--- installing second group "{0}" first ---' -f $OtherGroup) -ForegroundColor Cyan
        $otherPkg = (Resolve-Path -LiteralPath $OtherPackagePath).Path
        $otherFormat = Get-PackageFormat -Path $otherPkg
        $otherLog = Join-Path $WorkDir 'install-other.log'
        $otherExit = Invoke-PackageInstall -Path $otherPkg -LogPath $otherLog -Format $otherFormat
        Add-Result 'second group installs' ($otherExit -eq 0 -or $otherExit -eq 3010) ((Get-PackageFormat -Path $otherPkg) + ' exit ' + $otherExit + ', log ' + $otherLog)
    }
}

# ------------------------------------------------------------------ install ---
Write-Host ''
Write-Host '--- install ---' -ForegroundColor Cyan
$installToolLog = Join-Path $WorkDir ('install-' + $format + '.log')
if (Test-Path -LiteralPath $installToolLog) { Remove-Item -LiteralPath $installToolLog -Force }
$exitCode = Invoke-PackageInstall -Path $PackagePath -LogPath $installToolLog -Format $format
Add-Result 'install completes' ($exitCode -eq 0 -or $exitCode -eq 3010) ($format + ' exit ' + $exitCode + ' (0 = ok, 3010 = reboot suggested)')
if (-not ($exitCode -eq 0 -or $exitCode -eq 3010)) {
    Write-Host ''
    Write-Host 'install failed - last installer log lines:' -ForegroundColor Yellow
    Get-Content -LiteralPath $installToolLog -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkYellow }
}
Start-Sleep -Seconds 2

# ------------------------------------------------------- Add/Remove Programs ---
$arp = Get-ArpEntry -DisplayName $Group
Add-Result 'Add/Remove Programs shows the group name' ($arp.Count -eq 1) ('entries named "' + $Group + '": ' + $arp.Count)
$productCode = $null
if ($arp.Count -ge 1) {
    $entry = $arp[0]
    if ($format -eq 'msi') { $productCode = $entry.PSChildName }
    Add-Info ('entry key     : ' + $entry.PSChildName)
    Add-Info ('DisplayVersion: ' + $entry.DisplayVersion)
    Add-Info ('Publisher     : ' + $entry.Publisher)
    Add-Result 'publisher is EX SOFTWARE LLC' ($entry.Publisher -eq 'EX SOFTWARE LLC') ([string]$entry.Publisher)
    Add-Result 'entry is not the generic download file name' ($entry.DisplayName -ne 'exagent-setup') ([string]$entry.DisplayName)

    $loc = $null
    if ($entry.PSObject.Properties.Name -contains 'InstallLocation') { $loc = $entry.InstallLocation }
    $locOk = $false
    if ($loc) {
        $locNorm = ([string]$loc).TrimEnd('\')
        if (($locNorm -ieq $expectedFolder) -or ($locNorm -ieq $expectedInstallDir)) { $locOk = $true }
    }
    Add-Result 'Add/Remove Programs install location is the group folder' $locOk ([string]$loc)

    $comments = $null
    if ($entry.PSObject.Properties.Name -contains 'Comments') { $comments = $entry.Comments }
    Add-Result 'package metadata carries a mesh id' ($comments -and $comments -match 'MeshId=mesh//') ([string]$comments)

    $uninstallString = $null
    if ($entry.PSObject.Properties.Name -contains 'UninstallString') { $uninstallString = $entry.UninstallString }
    Add-Result 'uninstall entry is reachable' ([bool]$uninstallString) ([string]$uninstallString)
    if ($format -eq 'exe') {
        $uninstKeyOk = Test-Path -LiteralPath $uninstKey
        Add-Result 'per-group uninstall key exists' $uninstKeyOk $uninstKey
    }
} else {
    Add-Info 'no Add/Remove Programs entry for this group - see the install log above'
}

$byFileName = Get-ArpEntry -DisplayName 'exagent-setup'
Add-Result 'no entry named after the downloaded file' ($byFileName.Count -eq 0) ('entries named "exagent-setup": ' + $byFileName.Count)

# -------------------------------------------------------------------- files ---
Write-Host ''
Write-Host '--- installed files ---' -ForegroundColor Cyan
Add-Result 'install folder exists' (Test-Path -LiteralPath $expectedInstallDir) $expectedInstallDir
Add-Result 'agent binary installed' (Test-Path -LiteralPath $expectedAgent) $expectedAgent
if (Test-Path -LiteralPath $expectedAgent) {
    $agentInfo = Get-Item -LiteralPath $expectedAgent
    Add-Info ('agent size: ' + $agentInfo.Length + ' bytes')
    Add-Result 'agent binary is the expected size' ($agentInfo.Length -eq 3489888) ([string]$agentInfo.Length)
}
if ($format -eq 'msi') {
    Add-Result 'console-less service runner installed' (Test-Path -LiteralPath $expectedRunner) $expectedRunner
    if (Test-Path -LiteralPath $expectedRunner) {
        Add-Info ('runner size: ' + (Get-Item -LiteralPath $expectedRunner).Length + ' bytes')
    }
    Add-Result 'no stray repair helper in the MSI payload' (-not (Test-Path -LiteralPath $expectedHelper)) 'MSI carries the helper inside its runner'
} else {
    Add-Result 'service helper installed next to the agent' (Test-Path -LiteralPath $expectedHelper) $expectedHelper
}

# ----------------------------------------------------------------- registry ---
Write-Host ''
Write-Host '--- registry metadata ---' -ForegroundColor Cyan
$regOk = Test-Path -LiteralPath $regPath
Add-Result 'per-group registry key exists' $regOk $regPath
if ($regOk) {
    $meta = Get-ItemProperty -LiteralPath $regPath
    foreach ($field in @('ClientName', 'MeshId', 'ServerUrl', 'ServiceName', 'InstallDir')) {
        $value = $null
        if ($meta.PSObject.Properties.Name -contains $field) { $value = $meta.$field }
        Add-Result ('registry ' + $field + ' is populated') ([bool]$value) ([string]$value)
    }
    Add-Result 'registry ClientName is the group name' ($meta.ClientName -eq $Group) ([string]$meta.ClientName)
    Add-Result 'registry ServiceName matches the service' ($meta.ServiceName -eq $expectedService) ([string]$meta.ServiceName)
    Add-Result 'registry MeshId is a mesh id' ([string]$meta.MeshId -match '^mesh//') ([string]$meta.MeshId)
    Add-Result 'registry ServerUrl is the console URL' ([string]$meta.ServerUrl -match '^https?://') ([string]$meta.ServerUrl)
}

# ------------------------------------------------------------------ service ---
Write-Host ''
Write-Host '--- service ---' -ForegroundColor Cyan
$svc = Get-Service -Name $expectedService -ErrorAction SilentlyContinue
Add-Result 'service is registered under the group name' ([bool]$svc) ('service "' + $expectedService + '"')
if ($svc) {
    Add-Result 'service display name is the group name' ($svc.DisplayName -eq $Group) ([string]$svc.DisplayName)
    if (-not $svc.StartType) { $svc.Refresh() }
    Add-Result 'service start type is Automatic' (([string]$svc.StartType) -eq 'Automatic') ([string]$svc.StartType)
    if ($svc.Status -ne 'Running') {
        Add-Info 'service not running - attempting start'
        try { Start-Service -Name $expectedService -ErrorAction Stop; Start-Sleep -Seconds 3 } catch { Add-Info ('start failed: ' + $_.Exception.Message) }
        $svc = Get-Service -Name $expectedService -ErrorAction SilentlyContinue
    }
    Add-Result 'service is running' ($svc.Status -eq 'Running') ([string]$svc.Status)

    $binary = Get-ServiceBinary -Name $expectedService
    Add-Info ('service binary: ' + [string]$binary)
    $expectedAgentNorm = $expectedAgent.ToLowerInvariant()
    Add-Result 'service runs this group''s own agent copy' ($binary -and ($binary.ToLowerInvariant() -like ('*' + $expectedAgentNorm + '*'))) ([string]$binary)
    Add-Result 'service passes its own --meshServiceName' ($binary -and ($binary -match ('--meshServiceName="?' + [regex]::Escape($expectedService)))) ([string]$binary)
} else {
    Add-Info 'no service registered - checking for a legacy shared service'
    Get-Service -Name 'ExSoftwaresAgent' -ErrorAction SilentlyContinue | ForEach-Object { Add-Info ('  legacy shared service still present: ' + $_.Name + ' (' + $_.Status + ')') }
}

# ------------------------------------------------------- installer own log ---
Write-Host ''
Write-Host '--- installer log ---' -ForegroundColor Cyan
Add-Result 'installer wrote its per-group log' (Test-Path -LiteralPath $installLog) $installLog
if (Test-Path -LiteralPath $installLog) {
    $log = Get-Content -LiteralPath $installLog -ErrorAction SilentlyContinue
    Add-Info ('log lines: ' + $log.Count)
    Write-Host '  ---- agent-install.log (tail) ----' -ForegroundColor DarkGray
    $log | Select-Object -Last 25 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
    $joined = ($log -join "`n").ToLowerInvariant()
    Add-Result 'log reports the service reached Running' ($joined -match 'running') 'searched the log for a Running state'
    Add-Result 'log does not report a hard failure' (-not ($joined -match '\[error\]|failed to register|no service')) 'searched the log for [error]/registration failures'
}

# --------------------------------------------------------------- firewall ---
$fw = Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue
if ($fw -and $svc) {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $expectedService -or $_.Name -eq $expectedService }
    if ($rules) {
        Add-Result 'per-group firewall rule exists' $true $expectedService
    } else {
        Add-Info ('no firewall rule named ' + $expectedService + ' (informational: the agent makes outbound connections)')
    }
}

# --------------------------------------------------- second group coexistence ---
if ($OtherGroup) {
    Write-Host ''
    Write-Host ('--- coexistence with "{0}" ---' -f $OtherGroup) -ForegroundColor Cyan
    Add-Result 'other group install folder untouched' (Test-Path -LiteralPath $otherDir) $otherDir
    $otherArp = Get-ArpEntry -DisplayName $OtherGroup
    Add-Result 'other group still listed in Add/Remove Programs' ($otherArp.Count -eq 1) ('entries: ' + $otherArp.Count)
    $otherSvc = Get-Service -Name $otherService -ErrorAction SilentlyContinue
    Add-Result 'other group service still registered' ([bool]$otherSvc) $otherService
    if ($otherSvc) { Add-Result 'other group service still running' ($otherSvc.Status -eq 'Running') ([string]$otherSvc.Status) }
    Add-Result 'the two groups use different install folders' ($otherDir -ine $expectedFolder) ($otherDir + ' vs ' + $expectedFolder)
    Add-Result 'the two groups use different services' ($otherService -ine $expectedService) ($otherService + ' vs ' + $expectedService)
}

# ------------------------------------------------------------------ uninstall ---
if ($Uninstall) {
    Write-Host ''
    Write-Host '--- uninstall ---' -ForegroundColor Cyan
    $uninstallExit = $null
    if ($format -eq 'msi') {
        if (-not $productCode) {
            Add-Result 'uninstall possible' $false 'no ProductCode found for this group'
        } else {
            $uninstallLog = Join-Path $WorkDir 'uninstall-msi.log'
            $u = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x', $productCode, '/qn', '/norestart', '/l*v', ('"' + $uninstallLog + '"')) -Wait -PassThru
            $uninstallExit = $u.ExitCode
            Add-Result 'uninstall completes' ($u.ExitCode -eq 0 -or $u.ExitCode -eq 3010) ('msiexec exit ' + $u.ExitCode + ', log ' + $uninstallLog)
            if (-not ($u.ExitCode -eq 0 -or $u.ExitCode -eq 3010)) {
                Get-Content -LiteralPath $uninstallLog -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkYellow }
            }
        }
    } else {
        $uninstaller = Join-Path $expectedInstallDir 'uninstall.exe'
        if (-not (Test-Path -LiteralPath $uninstaller)) {
            Add-Result 'uninstall possible' $false ('uninstaller missing: ' + $uninstaller)
        } else {
            $u = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
            $uninstallExit = $u.ExitCode
            Add-Result 'uninstaller runs' ($true) ('exit ' + $u.ExitCode + ' (NSIS uninstaller relaunches itself from TEMP)')
            # The NSIS uninstaller copies itself to TEMP and returns at once, so
            # wait for the visible result instead of trusting the exit code.
            for ($i = 0; $i -lt 90; $i++) {
                if ((-not (Test-Path -LiteralPath $expectedInstallDir)) -and ((Get-ArpEntry -DisplayName $Group).Count -eq 0)) { break }
                Start-Sleep -Seconds 1
            }
            Add-Info ('waited ' + $i + 's for the uninstaller to finish')
        }
    }

    if ($format -eq 'msi' -or $uninstallExit -ne $null) {
        Start-Sleep -Seconds 2
        $leftArp = (Get-ArpEntry -DisplayName $Group).Count
        Add-Result 'Add/Remove Programs entry removed' ($leftArp -eq 0) ('entries left: ' + $leftArp)
        Add-Result 'install folder removed' (-not (Test-Path -LiteralPath $expectedInstallDir)) $expectedInstallDir
        Add-Result 'group folder removed' (-not (Test-Path -LiteralPath $expectedFolder)) $expectedFolder
        Add-Result 'service removed' (-not (Get-Service -Name $expectedService -ErrorAction SilentlyContinue)) $expectedService
        Add-Result 'registry key removed' (-not (Test-Path -LiteralPath $regPath)) $regPath
        if ($format -eq 'exe') {
            Add-Result 'uninstall key removed' (-not (Test-Path -LiteralPath $uninstKey)) $uninstKey
        }
        Add-Info ('log folder left in place by design (evidence for support): ' + (Split-Path -Parent $installLog))
        if ($OtherGroup) {
            $otherSvcAfter = Get-Service -Name $otherService -ErrorAction SilentlyContinue
            Add-Result 'other group survived this uninstall' ([bool]$otherSvcAfter -and (Test-Path -LiteralPath $otherDir)) $OtherGroup
        }
    }
}

# --------------------------------------------------------------------- report ---
Write-Host ''
Write-Host '--- summary ---' -ForegroundColor Cyan
$pass = ($script:Checks | Where-Object { $_.Result -eq 'PASS' }).Count
$fail = $script:Failures.Count
Write-Host ('  format: ' + $format + '   checks: ' + $script:Checks.Count + '   passed: ' + $pass + '   failed: ' + $fail)
if ($fail -gt 0) {
    Write-Host '  failures:' -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host ('   - ' + $f) -ForegroundColor Red }
}

$reportPath = Join-Path $WorkDir ('verify-report-' + $format + '.txt')
$script:Checks | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Add-Info ('report written to ' + $reportPath)
if (Test-Path -LiteralPath $installToolLog) { Add-Info ('installer log written to ' + $installToolLog) }

if ($fail -gt 0) { exit 1 }
exit 0
