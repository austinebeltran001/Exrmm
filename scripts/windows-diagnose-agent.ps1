# ============================================================================
# Ex Softwares RMM Agent - install / enrollment diagnostic (and repair)
# ============================================================================
# Symptom this script investigates:
#   The MSI reports success but the device never appears in the portal
#   dashboard, i.e. the agent never opens a WebSocket to
#   wss://remote.hackertreats.com:443/agent.ashx.
#
# It is read-only unless you pass -Repair.
#
# Usage (elevated PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\windows-diagnose-agent.ps1
#   powershell -ExecutionPolicy Bypass -File .\windows-diagnose-agent.ps1 -Repair
#
# -Repair does what the MSI's deferred custom action does, but visibly:
#   * stops and deletes a stale / orphaned agent service, if one is present
#     (a service whose binary no longer exists, left behind by an earlier
#     uninstall that removed the files by hand)
#   * runs  ex-softwares-agent.exe -fullinstall  and shows its output
#   * starts the service and reports whether it is running
#
# Everything printed is safe to paste into a chat / ticket. No secrets are
# read: the script never opens the agent's .db, only lists it.
# ============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Repair
)

$ErrorActionPreference = 'Continue'
$InstallDir = Join-Path $env:ProgramFiles 'ExSoftwares\Agent'
$AgentExe   = Join-Path $InstallDir 'ex-softwares-agent.exe'
$RunnerExe  = Join-Path $InstallDir 'ex-softwares-agent-svc.exe'

function Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Note([string]$Text) {
    Write-Host ("  {0}" -f $Text)
}

function Get-AgentServices {
    # Any service whose binary lives in our install directory. Matching on the
    # image path is more reliable than guessing the SCM name, which differs
    # between MeshCentral builds ("Mesh Agent", "MeshAgent", ...).
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.PathName -and $_.PathName -match 'Ex Softwares LLC') -or
            ($_.PathName -and $_.PathName -match 'MeshAgent\.exe') -or
            ($_.Name -match '^(Mesh|MeshAgent|Ex Softwares LLC)')
        }
}

function Show-Services {
    $svc = @(Get-AgentServices)
    if ($svc.Count -eq 0) {
        Note 'NO agent service is registered on this machine.'
        Note 'That means the install completed but the service-registration step'
        Note '(-fullinstall) never succeeded - the agent cannot run, so it can'
        Note 'never appear in the portal.'
        return
    }
    foreach ($s in $svc) {
        Note ("Name        : {0}" -f $s.Name)
        Note ("DisplayName : {0}" -f $s.DisplayName)
        Note ("State       : {0}   StartMode: {1}" -f $s.State, $s.StartMode)
        Note ("StartName   : {0}" -f $s.StartName)
        Note ("PathName    : {0}" -f $s.PathName)
        $bin = $null
        if ($s.PathName -match '^"([^"]+)"') { $bin = $Matches[1] }
        elseif ($s.PathName -match '^(\S+\.exe)') { $bin = $Matches[1] }
        if ($bin) {
            Note ("Binary exists: {0}  ({1})" -f (Test-Path $bin), $bin)
        }
        Note ''
    }
}

function Show-Product {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $found = $false
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.DisplayName -like 'Ex Softwares LLC*') {
                $found = $true
                Note ("DisplayName    : {0}" -f $p.DisplayName)
                Note ("DisplayVersion : {0}" -f $p.DisplayVersion)
                Note ("ProductCode    : {0}" -f $_.PSChildName)
                Note ("InstallLocation: {0}" -f $p.InstallLocation)
                Note ("UninstallString: {0}" -f $p.UninstallString)
                Note ''
            }
        }
    }
    if (-not $found) {
        Note 'No "Ex Softwares RMM Agent" entry in Apps & features.'
    }
}

function Show-Files {
    if (-not (Test-Path $InstallDir)) {
        Note ("Install directory MISSING: {0}" -f $InstallDir)
        return
    }
    Note ("Directory: {0}" -f $InstallDir)
    Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = ''
        if ($_.Length -lt 20MB -and $_.Extension -ne '.db') {
            try { $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash } catch { $hash = '' }
        }
        Note ("  {0,-32} {1,12}  {2}  {3}" -f $_.Name, $_.Length, $_.LastWriteTime.ToString('u'), $hash)
    }

    if (Test-Path $AgentExe) {
        $sig = Get-AuthenticodeSignature $AgentExe -ErrorAction SilentlyContinue
        Note ''
        Note ("Agent signature: {0}" -f $(if ($sig) { $sig.Status } else { 'unknown' }))
        $ver = (Get-Item $AgentExe).VersionInfo
        Note ("Agent file version: {0}" -f $ver.FileVersion)
    }
}

function Show-AgentMesh {
    # The MeshCentral agent carries its device-group binding in a small
    # \r\nMeshName=...\r\nMeshType=...\r\nMeshID=0x...\r\n block embedded in
    # the executable. Reading it back proves which group THIS binary will
    # enrol into - useful when a machine keeps showing up in an older group
    # after a reinstall.
    if (-not (Test-Path $AgentExe)) {
        Note ("Agent binary missing: {0}" -f $AgentExe)
        return
    }
    try {
        $raw = [System.IO.File]::ReadAllBytes($AgentExe)
        $text = [System.Text.Encoding]::ASCII.GetString($raw)
        $m = [regex]::Match($text, 'MeshName=(?<name>[^\r\n]*)[\r\n]+MeshType=(?<type>\d+)[\r\n]+MeshID=(?<id>0x[0-9A-Fa-f]+)')
        if ($m.Success) {
            Note ("Embedded MeshName : {0}" -f $m.Groups['name'].Value)
            Note ("Embedded MeshType : {0}" -f $m.Groups['type'].Value)
            Note ("Embedded MeshID   : {0}" -f $m.Groups['id'].Value)
        } else {
            Note 'No embedded MeshName/MeshID block found in the agent binary.'
            Note 'This binary would install a service with no device group.'
        }
    } catch {
        Note ("Could not read the agent binary: {0}" -f $_.Exception.Message)
    }
}

function Show-InstallLog {
    # Written by ex-softwares-agent-svc.exe, the console-less runner the MSI
    # executes for -fullinstall / -fulluninstall. The MSI runs that action with
    # Return="ignore", so this file is the only place a failure is recorded.
    $log = Join-Path (Join-Path $env:ProgramData 'Ex Softwares LLC') 'agent-install.log'
    if (-not (Test-Path $log)) {
        Note ("No runner log at {0}" -f $log)
        Note 'Either the MSI used an older runner, or the action never ran.'
        return
    }
    $item = Get-Item $log
    Note ("{0} ({1} bytes, last write {2})" -f $item.FullName, $item.Length, $item.LastWriteTime.ToString('u'))
    Get-Content $log -ErrorAction SilentlyContinue | ForEach-Object { Note ("    " + $_) }
}

function Show-Processes {
    # Match on the image path (the MSI installs into %ProgramFiles%\Ex Softwares LLC)
    # and on the process name, because -fullinstall copies the agent to
    # %ProgramFiles%\Mesh Agent and runs it as MeshAgent.exe.
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $byPath = $false
        try { $byPath = ($_.Path -and $_.Path -match 'Ex Softwares LLC|Mesh Agent') } catch { $byPath = $false }
        $byPath -or $_.ProcessName -match '^(MeshAgent|ExSoftwaresAgent)'
    })
    if ($procs.Count -eq 0) {
        Note 'No running agent process (MeshAgent / ExSoftwaresAgent) found.'
        return
    }
    foreach ($p in $procs) {
        Note ("PID {0,-6} {1}" -f $p.Id, $p.Path)
    }
}

function Show-Logs {
    $candidates = @()
    if (Test-Path $InstallDir) {
        $candidates += Get-ChildItem $InstallDir -Filter '*.log' -ErrorAction SilentlyContinue
        $candidates += Get-ChildItem $InstallDir -Filter 'meshagent.*' -ErrorAction SilentlyContinue
    }
    $progData = Join-Path $env:ProgramData 'MeshAgent'
    if (Test-Path $progData) {
        $candidates += Get-ChildItem $progData -Filter '*.log' -ErrorAction SilentlyContinue
    }
    $htData = Join-Path $env:ProgramData 'Ex Softwares LLC'
    if (Test-Path $htData) {
        $candidates += Get-ChildItem $htData -Filter '*.log' -ErrorAction SilentlyContinue
    }

    if ($candidates.Count -eq 0) {
        Note 'No agent log files found.'
        return
    }
    foreach ($f in $candidates) {
        Note ("--- {0} ({1} bytes, {2})" -f $f.FullName, $f.Length, $f.LastWriteTime.ToString('u'))
        try {
            Get-Content $f.FullName -Tail 40 -ErrorAction Stop | ForEach-Object { Note ("    " + $_) }
        } catch {
            Note ("    (could not read: {0})" -f $_.Exception.Message)
        }
        Note ''
    }
}

function Show-Defender {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Note ("Real-time protection: {0}" -f $mp.RealTimeProtectionEnabled)
        $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Where-Object { $_.Resources -match 'Ex Softwares LLC|meshagent' })
        if ($det.Count -eq 0) {
            Note 'No Defender detections referencing the agent.'
        } else {
            foreach ($d in $det) {
                Note ("DETECTED {0}: {1}" -f $d.InitialDetectionTime, ($d.Resources -join '; '))
            }
        }
    } catch {
        Note 'Defender status unavailable (third-party AV or cmdlet missing).'
    }
}

function Show-Network {
    $host_ = 'remote.hackertreats.com'
    try {
        $dns = Resolve-DnsName $host_ -Type A -ErrorAction Stop |
            Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
        Note ("DNS  {0} -> {1}" -f $host_, ($dns -join ', '))
    } catch {
        Note ("DNS resolution FAILED: {0}" -f $_.Exception.Message)
    }

    try {
        $tcp = Test-NetConnection -ComputerName $host_ -Port 443 -WarningAction SilentlyContinue
        Note ("TCP  443 reachable: {0}  (remote {1})" -f $tcp.TcpTestSucceeded, $tcp.RemoteAddress)
    } catch {
        Note ("TCP test FAILED: {0}" -f $_.Exception.Message)
    }

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($host_, 443)
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))
        $ssl.AuthenticateAsClient($host_)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        Note ("TLS  subject: {0}" -f $cert.Subject)
        Note ("TLS  issuer : {0}" -f $cert.Issuer)
        Note ("TLS  expires: {0}" -f $cert.NotAfter.ToString('u'))
        Note ("TLS  sha1   : {0}" -f $cert.Thumbprint)
        $ssl.Close(); $client.Close()
    } catch {
        Note ("TLS handshake FAILED: {0}" -f $_.Exception.Message)
    }

    try {
        $proxy = netsh winhttp show proxy
        Note ''
        Note 'WinHTTP proxy:'
        $proxy | ForEach-Object { Note ("    " + $_) }
    } catch { }
}

function Invoke-Repair {
    Section 'REPAIR'

    if (-not (Test-Path $AgentExe)) {
        Write-Host '  Agent binary is missing - nothing to repair. Reinstall the MSI.' -ForegroundColor Red
        return
    }

    # 1. Remove a stale service registration (binary gone, or duplicate names).
    foreach ($s in @(Get-AgentServices)) {
        $bin = $null
        if ($s.PathName -match '^"([^"]+)"') { $bin = $Matches[1] }
        elseif ($s.PathName -match '^(\S+\.exe)') { $bin = $Matches[1] }
        $stale = $false
        if ($bin -and -not (Test-Path $bin)) { $stale = $true }
        if ($stale) {
            Write-Host ("  removing stale service '{0}' -> missing binary {1}" -f $s.Name, $bin) -ForegroundColor Yellow
            & sc.exe stop $s.Name | Out-Null
            Start-Sleep -Seconds 2
            & sc.exe delete $s.Name | Out-Null
            Start-Sleep -Seconds 2
        } else {
            Write-Host ("  stopping existing service '{0}' before re-registering" -f $s.Name) -ForegroundColor Yellow
            & sc.exe stop $s.Name | Out-Null
            Start-Sleep -Seconds 2
        }
    }

    # 2. Run the same command the MSI's deferred custom action runs, visibly.
    $outFile = Join-Path $env:TEMP 'ht-agent-fullinstall.out.txt'
    $errFile = Join-Path $env:TEMP 'ht-agent-fullinstall.err.txt'
    Write-Host '  running: ex-softwares-agent.exe -fullinstall' -ForegroundColor Yellow
    $p = Start-Process -FilePath $AgentExe -ArgumentList '-fullinstall' -Wait -PassThru `
        -NoNewWindow -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    Write-Host ("  exit code: {0}" -f $p.ExitCode)

    if (Test-Path $outFile) {
        Get-Content $outFile | ForEach-Object { Note ("  out| " + $_) }
    }
    if (Test-Path $errFile) {
        Get-Content $errFile | ForEach-Object { Note ("  err| " + $_) }
    }

    # 3. Verify and start.
    Start-Sleep -Seconds 3
    $svc = @(Get-AgentServices)
    if ($svc.Count -eq 0) {
        Write-Host '  Still NO service registered. The agent binary failed to install itself.' -ForegroundColor Red
        Write-Host '  Send the output above - it contains the agent''s own error message.' -ForegroundColor Red
        return
    }
    foreach ($s in $svc) {
        if ($s.State -ne 'Running') {
            Write-Host ("  starting service '{0}'" -f $s.Name) -ForegroundColor Yellow
            try { Start-Service -Name $s.Name -ErrorAction Stop } catch {
                Write-Host ("  start failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            }
        }
    }
    Start-Sleep -Seconds 8
    Section 'REPAIR RESULT'
    Show-Services
    Show-Processes
    Show-Logs
    Write-Host '  If the service is now Running, the device should appear in the' -ForegroundColor Green
    Write-Host '  dashboard within ~30 seconds (refresh the page).' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Section 'HOST'
Note ("Computer : {0}" -f $env:COMPUTERNAME)
Note ("User     : {0}" -f $env:USERNAME)
Note ("Time     : {0}" -f (Get-Date).ToString('u'))
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Note ("OS       : {0} {1} ({2})" -f $os.Caption, $os.Version, $os.OSArchitecture)
} catch { }

Section 'PRODUCT REGISTRATION'
Show-Product

Section 'INSTALLED FILES'
Show-Files

Section 'AGENT MESH BINDING'
Show-AgentMesh

Section 'INSTALL RUNNER LOG'
Show-InstallLog

Section 'AGENT SERVICE'
Show-Services

Section 'RUNNING PROCESSES'
Show-Processes

Section 'AGENT METADATA (HKLM\Software\ExSoftwares\Agent)'
$key = 'HKLM:\Software\ExSoftwares\Agent'
if (Test-Path $key) {
    $v = Get-ItemProperty $key
    Note ("ClientName : {0}" -f $v.ClientName)
    Note ("MeshId     : {0}" -f $v.MeshId)
    Note ("ServerUrl  : {0}" -f $v.ServerUrl)
    Note ("InstalledBy: {0}" -f $v.InstalledBy)
} else {
    Note 'Registry key missing (the MSI did not complete).'
}

Section 'AGENT LOGS'
Show-Logs

Section 'ENDPOINT DEFENDER'
Show-Defender

Section 'NETWORK PATH TO THE SERVER'
Show-Network

if ($Repair) {
    Invoke-Repair
}

Section 'WHAT TO LOOK AT'
Write-Host @'
  1. AGENT SERVICE shows "NO agent service is registered"
        -> the install placed the files but -fullinstall did not register the
           service. Run this script again with -Repair; the agent prints its
           own failure reason.
  2. A service exists but State is Stopped / its binary does not exist
        -> stale registration from an earlier uninstall. Run with -Repair.
  3. Service is Running but the device is still absent in the dashboard
        -> look at the last lines of the agent log: a TLS or proxy error there
           means the machine cannot reach wss://remote.hackertreats.com:443.
           The NETWORK section shows whether DNS/TCP/TLS work at all.
  4. Defender shows a detection for ex-softwares-agent.exe
        -> the AV removed the binary; add an exclusion for
           C:\Program Files\ExSoftwares\Agent and reinstall.
  5. AGENT MESH BINDING names a different group than the one you downloaded
        -> this machine is still running an agent from an earlier group. The
           old service was never replaced: stop it, run
           "<install dir>\ex-softwares-agent.exe -fulluninstall", delete the
           install directory, then install the new MSI.
'@
