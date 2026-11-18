<#
.SYNOPSIS
    Installs, repairs or removes one device group's RMM agent Windows service.

.DESCRIPTION
    Invoked by the MSI's console-less service runner (scripts/msi-runner.nsi)
    from a deferred custom action, and usable by hand for a one-off repair:

        powershell -ExecutionPolicy Bypass -File agent-service-install.ps1 `
            -Mode install `
            -AgentPath "C:\Program Files\Exagent1999\Agent\ex-softwares-agent.exe" `
            -ServiceName ExSoftwaresAgent_exagent1999 `
            -DisplayName "Exagent1999" `
            -InstallDir "C:\Program Files\Exagent1999\Agent"

    Every name this helper writes comes from the device group the installer was
    built for: the service is named after the group, its display name *is* the
    group name, and the log lives in a per-group folder.

    Why this file exists
    --------------------
    The MeshCentral agent's own `-fullinstall` is wrong for a multi-group
    product, in two independent ways:

      * It is not idempotent and reports success by exit code even when it
        registered nothing: it copies itself to "%ProgramFiles%\Mesh Agent"
        and, if that copy fails (stale service still running from that exact
        path, locked file), never creates the service - and still exits 0. The
        MSI runs the runner with Return="ignore", so the result would be an
        agent that never phones home.

      * Its identity is global. It always uses the ONE folder
        "%ProgramFiles%\Mesh Agent" and the ONE service name baked into the
        binary (ExSoftwaresAgent, from the portal's meshServiceName). Two
        device groups installed on the same machine therefore cannot coexist:
        the second install overwrites the first group's payload and hijacks
        its service, so the first group silently stops reporting.

    So this helper does not use `-fullinstall` as its primary path. It:

      1. stops agent processes and deletes services that belong to THIS group
         only - by service name, by image path inside this group's install
         directory, or (for leftovers of the old one-service-per-machine
         installer) by an image path whose agent binary is byte-identical to
         this group's agent. Anything else is left running and logged, because
         it belongs to a different device group;
      2. registers the service directly against the MSI-installed agent in this
         group's own folder, with `--meshServiceName="<group service>"`, so the
         agent knows which service to control on self-update;
      3. starts it and verifies it really reached the Running state;
      4. adds a firewall rule named after the group's service (a shared rule
         name would have group B delete group A's rule);
      5. logs every step to %ProgramData%\EXagent\<group>\agent-install.log and
         returns a non-zero exit code when the machine still has no service.

    `-fullinstall` is still used as a last-resort fallback when direct
    registration fails, and the service it creates is then re-registered under
    this group's name.

    -Mode uninstall stops and deletes only this group's service and processes,
    removes this group's firewall rule, and cleans up the old shared payload
    only when its binary is this group's agent.

.NOTES
    Runs under Windows PowerShell 5.1 (the only PowerShell guaranteed on a
    stock Windows 10/11 machine) and must stay compatible with it. It is
    executed elevated (SYSTEM during the MSI deferred action).
#>

[CmdletBinding()]
param(
    [ValidateSet('install', 'uninstall')]
    [string]$Mode = 'install',

    # Installed agent binary that carries the .msh config (mesh id + server).
    [Parameter(Mandatory = $true)]
    [string]$AgentPath,

    # SCM name of this device group's service.
    [string]$ServiceName = 'ExSoftwaresAgent',

    # Name shown in services.msc / Task Manager: the device group name.
    [string]$DisplayName = 'Ex Softwares RMM Agent',

    # This group's install directory ($EXEDIR of the runner). Only services and
    # processes below it are considered ours.
    [string]$InstallDir,

    # Override for the log file; defaults to %ProgramData%\EXagent\<group>\...
    [string]$LogPath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- identity ---

$script:AgentPath = $AgentPath
if ($InstallDir) {
    $script:AgentDir = $InstallDir
} else {
    $script:AgentDir = Split-Path -Parent $AgentPath
}
$script:GroupLabel = Split-Path -Leaf $script:AgentDir
# The install directory is "<group>\Agent", so the group label is one level up.
if ($script:GroupLabel -ieq 'Agent') {
    $parentDir = Split-Path -Parent $script:AgentDir
    if ($parentDir) { $script:GroupLabel = Split-Path -Leaf $parentDir }
}
if (-not $script:GroupLabel) { $script:GroupLabel = 'agent' }

function Get-NormalizedPath {
    param([string]$Path)
    if (-not $Path) { return '' }
    $value = $Path.Trim()
    if ($value.StartsWith('"')) { $value = $value.Trim('"') }
    try { $value = [System.IO.Path]::GetFullPath($value) } catch { }
    return $value.TrimEnd('\').ToLowerInvariant()
}

$script:AgentDirNorm = Get-NormalizedPath $script:AgentDir

# ---------------------------------------------------------------- logging ---

if ($LogPath) {
    $script:LogFile = $LogPath
} else {
    $programData = $env:ProgramData
    if (-not $programData) { $programData = 'C:\ProgramData' }
    $script:LogFile = Join-Path (Join-Path (Join-Path $programData 'EXagent') $script:GroupLabel) 'agent-install.log'
}

$script:LogDir = Split-Path -Parent $script:LogFile
if ($script:LogDir -and -not (Test-Path -LiteralPath $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force -ErrorAction SilentlyContinue | Out-Null
}

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    # Write-Host, not Write-Output: log lines must not leak into the pipeline,
    # otherwise a function's return value becomes an array of log strings and
    # callers such as `if (-not (New-AgentService ...))` misread it as success.
    # Host output still reaches stdout when PowerShell runs under nsExec.
    Write-Host $line
    try {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Logging must never be the reason an install fails.
    }
}

# ------------------------------------------------------------ identification ---

# Names used by older builds of this agent. They are only ever removed when the
# binary behind them is provably this group's agent (see Test-ServiceIsOurs),
# because a shared name says nothing about which device group owns it.
$script:LegacyNames = @(
    'ExSoftwaresAgent',
    'MeshAgent',
    'Mesh Agent',
    'Ex Softwares Agent',
    'Ex Softwares RMM Agent'
)

# Matching on the file name only: an image path may be quoted, may contain
# arguments (the agent registers `"<path>" --meshServiceName="..."`) and may
# be a path that no longer exists.
$script:PathPattern = '(?i)(meshagent\.exe|ex-softwares-agent[^\\/]*\.exe)'

$script:AgentHash = $null
function Get-AgentHash {
    if ($script:AgentHash) { return $script:AgentHash }
    if (-not (Test-Path -LiteralPath $script:AgentPath)) { return $null }
    try {
        $script:AgentHash = (Get-FileHash -LiteralPath $script:AgentPath -Algorithm SHA256).Hash
    } catch {
        Write-Log ('could not hash {0}: {1}' -f $script:AgentPath, $_.Exception.Message)
        return $null
    }
    return $script:AgentHash
}

function Test-BinaryIsThisGroup {
    param([string]$Path)
    if (-not $Path) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $expected = Get-AgentHash
    if (-not $expected) { return $false }
    try {
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } catch {
        return $false
    }
    return $actual -eq $expected
}

function Test-PathInInstallDir {
    param([string]$Path)
    if (-not $Path) { return $false }
    $norm = Get-NormalizedPath $Path
    if (-not $norm) { return $false }
    if ($norm -eq $script:AgentDirNorm) { return $true }
    return $norm.StartsWith($script:AgentDirNorm + '\')
}

function Get-AgentProgramRoots {
    # ProgramW6432 is the real "C:\Program Files" even from 32-bit PowerShell
    # (the runner is a 32-bit NSIS binary, so $env:ProgramFiles can point at the
    # x86 directory). Deduplicated, because on 64-bit PowerShell both names
    # resolve to the same path.
    $roots = @()
    if ($env:ProgramW6432) { $roots += $env:ProgramW6432 }
    if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
    return @($roots | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ServiceImagePath {
    param([string]$Name)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction SilentlyContinue
    if (-not $svc -or -not $svc.PathName) { return $null }
    $path = $svc.PathName.Trim()
    if ($path.StartsWith('"')) {
        $end = $path.IndexOf('"', 1)
        if ($end -gt 1) { return $path.Substring(1, $end - 1) }
    }
    if ($path -match '^(.+?\.exe)\b') { return $Matches[1] }
    return $path
}

function Get-AgentService {
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $name = $_.Name
        $path = $_.PathName
        ($name -and ($name -eq $ServiceName)) -or
        ($name -and ($script:LegacyNames -contains $name)) -or
        ($path -and ($path -match $script:PathPattern))
    }
}

function Test-ServiceIsOurs {
    param($Service)
    if (-not $Service) { return $false }
    if ($Service.Name -eq $ServiceName) { return $true }
    $image = Get-ServiceImagePath -Name $Service.Name
    if (Test-PathInInstallDir $image) { return $true }
    # Leftover of the old shared-payload installer: only ours when the binary
    # it runs is byte-identical to this group's agent. Same service name, same
    # folder for every group in that installer - the hash is what tells the
    # groups apart.
    if (Test-BinaryIsThisGroup $image) {
        Write-Log ('service {0} runs this group''s agent from the shared legacy payload ({1})' -f $Service.Name, $image)
        return $true
    }
    return $false
}

function Get-AgentProcess {
    $names = @('ex-softwares-agent', 'ex-softwares-agent-svc', 'MeshAgent', 'ExSoftwaresAgent', 'Ex Softwares LLC')
    foreach ($n in $names) {
        $procs = @(Get-Process -Name $n -ErrorAction SilentlyContinue)
        foreach ($proc in $procs) {
            if ($proc) { $proc }
        }
    }
}

# ------------------------------------------------------------------ cleanup ---

function Stop-AgentProcesses {
    foreach ($proc in @(Get-AgentProcess)) {
        $path = $null
        try { $path = $proc.Path } catch { $path = $null }
        if (-not (Test-PathInInstallDir $path) -and -not (Test-BinaryIsThisGroup $path)) {
            Write-Log ('leaving process {0} (pid {1}) alone: not this device group''s agent ({2})' -f $proc.ProcessName, $proc.Id, $path)
            continue
        }
        try {
            Write-Log ('stopping process {0} (pid {1})' -f $proc.ProcessName, $proc.Id)
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            Write-Log ('could not stop process {0}: {1}' -f $proc.ProcessName, $_.Exception.Message)
        }
    }
    # Give the SCM/kernel a moment to release the image file handles.
    Start-Sleep -Milliseconds 600
}

function Remove-AgentServices {
    $removed = 0
    foreach ($svc in @(Get-AgentService)) {
        $name = $svc.Name
        Write-Log ('found service {0} (state={1}, start={2}, path={3})' -f $name, $svc.State, $svc.StartMode, $svc.PathName)

        if (-not (Test-ServiceIsOurs -Service $svc)) {
            Write-Log ('keeping service {0}: it belongs to a different device group' -f $name)
            continue
        }

        if ($svc.State -ne 'Stopped') {
            try {
                Stop-Service -Name $name -Force -ErrorAction Stop
                Write-Log ('stopped service {0}' -f $name)
            } catch {
                & sc.exe stop "$name" | Out-Null
                Write-Log ('sc stop {0}: {1}' -f $name, $_.Exception.Message)
            }
            Start-Sleep -Milliseconds 700
        }

        # A service that is still marked for deletion returns 1072 until the
        # last handle closes, so retry instead of assuming the first call won.
        $deleted = $false
        for ($i = 0; $i -lt 6; $i++) {
            & sc.exe delete "$name" | Out-Null
            Start-Sleep -Milliseconds 500
            if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
                $deleted = $true
                break
            }
        }
        if ($deleted) {
            Write-Log ('deleted service {0}' -f $name)
            $removed++
        } else {
            Write-Log ('WARNING: service {0} is still registered (marked for deletion?)' -f $name)
        }
    }
    return $removed
}

function Remove-LegacyPayloadFolder {
    # Only the old installer created "%ProgramFiles%\Mesh Agent". Remove it when
    # the agent in it is this group's agent and no remaining service still runs
    # from that directory (another group's service would keep it alive).
    $stillUsed = $false
    foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
        if ($svc.PathName -and ($svc.PathName -match '(?i)mesh agent')) { $stillUsed = $true; break }
    }
    if ($stillUsed) {
        Write-Log 'shared "Mesh Agent" payload still used by another service; left in place'
        return
    }
    foreach ($root in @(Get-AgentProgramRoots)) {
        $dir = Join-Path $root 'Mesh Agent'
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $binary = Join-Path $dir 'MeshAgent.exe'
        if ((Test-Path -LiteralPath $binary) -and -not (Test-BinaryIsThisGroup $binary)) {
            Write-Log ('shared "Mesh Agent" payload at {0} belongs to another device group; left in place' -f $dir)
            continue
        }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $dir) {
            Write-Log ('leftover folder kept (in use): {0}' -f $dir)
        } else {
            Write-Log ('removed leftover shared payload {0}' -f $dir)
        }
    }
}

# --------------------------------------------------------------- firewall ---

function Add-AgentFirewallRule {
    param([string]$Binary)
    # Rule name is the per-group service name: a fixed name would make each
    # group's install delete the other group's rule.
    $ruleName = $ServiceName
    & netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
    & netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow program="$Binary" enable=yes profile=any | Out-Null
    Write-Log ('firewall rule "{0}" -> {1}' -f $ruleName, $Binary)
}

function Remove-AgentFirewallRule {
    & netsh advfirewall firewall delete rule name="$ServiceName" | Out-Null
    Write-Log ('firewall rule "{0}" removed' -f $ServiceName)
}

# ------------------------------------------------------- the agent's own CA ---

function Invoke-Agent {
    param([string]$Arguments)
    if (-not (Test-Path -LiteralPath $script:AgentPath)) {
        Write-Log ('agent binary not found: {0}' -f $script:AgentPath)
        return 127
    }
    Write-Log ('running "{0}" {1}' -f $script:AgentPath, $Arguments)
    try {
        $output = & $script:AgentPath $Arguments 2>&1
        $code = $LASTEXITCODE
    } catch {
        Write-Log ('agent failed to start: {0}' -f $_.Exception.Message)
        return 126
    }
    foreach ($line in @($output)) {
        $text = [string]$line
        if ($text.Trim()) { Write-Log ('agent: ' + $text.Trim()) }
    }
    Write-Log ('agent exit code: {0}' -f $code)
    return $code
}

# --------------------------------------------------- explicit registration ---

function New-AgentService {
    param(
        [string]$Name,
        [string]$Binary,
        [string]$Title
    )
    # Same command line the agent writes itself: the service name is passed
    # back to the agent so it knows which service to control on self-update.
    $binaryPath = '"{0}" --meshServiceName="{1}"' -f $Binary, $Name
    if (-not $Title) { $Title = $DisplayName }
    $description = '{0} - EX SOFTWARE LLC remote monitoring agent.' -f $Title

    if (-not (Test-Path -LiteralPath $Binary)) {
        Write-Log ('cannot register service: binary missing: {0}' -f $Binary)
        return $false
    }

    try {
        New-Service -Name $Name `
            -BinaryPathName $binaryPath `
            -DisplayName $Title `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null
        Write-Log ('created service {0} -> {1}' -f $Name, $binaryPath)
    } catch {
        Write-Log ('New-Service failed: {0}' -f $_.Exception.Message)
        & sc.exe create "$Name" binPath= "$binaryPath" start= auto DisplayName= "$Title" | Out-Null
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            Write-Log ('sc create also failed for {0}' -f $Name)
            return $false
        }
        Write-Log ('created service {0} via sc.exe' -f $Name)
    }

    & sc.exe description "$Name" "$description" | Out-Null
    & sc.exe failure "$Name" reset= 86400 actions= restart/60000/restart/60000/restart/120000 | Out-Null
    return $true
}

function Start-AgentService {
    param([string]$Name)
    for ($i = 0; $i -lt 3; $i++) {
        try {
            Start-Service -Name $Name -ErrorAction Stop
        } catch {
            & sc.exe start "$Name" | Out-Null
        }
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Log ('service {0} is running' -f $Name)
            return $true
        }
        if ($svc) {
            Write-Log ('service {0} state after start attempt: {1}' -f $Name, $svc.Status)
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ------------------------------------------------------------------- modes ---

function Invoke-InstallMode {
    Write-Log '---- install requested ----'
    Write-Log ('agent:   {0}' -f $script:AgentPath)
    Write-Log ('group:   {0}' -f $DisplayName)
    Write-Log ('service: {0} ({1})' -f $ServiceName, $DisplayName)
    Write-Log ('folder:  {0}' -f $script:AgentDir)

    if (-not (Test-Path -LiteralPath $script:AgentPath)) {
        Write-Log ('FAILED: agent binary missing at {0}' -f $script:AgentPath)
        return 1
    }

    Stop-AgentProcesses
    [void](Remove-AgentServices)

    if (-not (New-AgentService -Name $ServiceName -Binary $script:AgentPath -Title $DisplayName)) {
        # Last resort: let the agent install itself the old way, then take over
        # whatever identity it produced so this group still owns the service.
        Write-Log 'direct registration failed; falling back to the agent''s own -fullinstall'
        [void](Invoke-Agent '-fullinstall')
        Start-Sleep -Seconds 1
        $adopted = $null
        foreach ($svc in @(Get-AgentService)) {
            if (Test-ServiceIsOurs -Service $svc) {
                $adopted = Get-ServiceImagePath -Name $svc.Name
                Write-Log ('adopting payload {0} from service {1}' -f $adopted, $svc.Name)
                break
            }
        }
        [void](Remove-AgentServices)
        if (-not $adopted) { $adopted = $script:AgentPath }
        if (-not (New-AgentService -Name $ServiceName -Binary $adopted -Title $DisplayName)) {
            Write-Log 'FAILED: no service could be registered'
            return 1
        }
    }

    Add-AgentFirewallRule -Binary (Get-ServiceImagePath -Name $ServiceName)

    $running = Start-AgentService -Name $ServiceName
    if (-not $running) {
        Write-Log 'FAILED: service exists but did not reach the Running state'
        return 1
    }

    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log ('registered: name={0} display={1} state={2} start={3} path={4}' -f $svc.Name, $svc.DisplayName, $svc.State, $svc.StartMode, $svc.PathName)
    }
    Write-Log 'install completed'
    return 0
}

function Remove-AgentStateFiles {
    # Windows Installer only removes the two files it installed. The agent
    # writes its own runtime state next to its binary (the pinned MeshCentral
    # configuration *.msh and its *.db), so those leftovers kept the per-group
    # folder behind after an uninstall - RemoveFolder only deletes an empty
    # directory, and the machine was left with an orphaned "C:\Program Files\
    # <group>" tree. The folder belongs to this product, so anything in it that
    # is not a file the MSI installs is state and goes.
    if (-not $script:AgentDir -or -not (Test-Path -LiteralPath $script:AgentDir)) { return }
    $installed = @('ex-softwares-agent-svc.exe')
    if ($script:AgentPath) { $installed += [System.IO.Path]::GetFileName($script:AgentPath) }
    $removed = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $script:AgentDir -File -Force -ErrorAction SilentlyContinue)) {
        if ($installed -contains $file.Name) { continue }
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $removed++
        } catch {
            Write-Log ('could not remove state file {0}: {1}' -f $file.Name, $_.Exception.Message)
        }
    }
    Write-Log ('removed {0} agent state file(s) from {1}' -f $removed, $script:AgentDir)
    # This action is deferred, so it actually runs at InstallFinalize - AFTER
    # Windows Installer removed its own two files (RemoveFiles, 3500) and after
    # RemoveFolders (same sequence) already tried and failed, because the state
    # files were still there at that point. Prune the folders here, and only
    # when each one is empty: "%ProgramFiles%\<group>" and its "\Agent" child.
    foreach ($folder in @($script:AgentDir, (Split-Path -Parent $script:AgentDir))) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        if (@(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue).Count -gt 0) { continue }
        try {
            Remove-Item -LiteralPath $folder -Force -ErrorAction Stop
            Write-Log ('removed empty folder {0}' -f $folder)
        } catch {
            Write-Log ('could not remove folder {0}: {1}' -f $folder, $_.Exception.Message)
        }
    }
}


function Invoke-UninstallMode {
    Write-Log '---- uninstall requested ----'
    Write-Log ('group:   {0}' -f $DisplayName)
    Write-Log ('service: {0}' -f $ServiceName)
    # No agent -fulluninstall here: it would tear down the shared
    # "%ProgramFiles%\Mesh Agent" install and the shared service name, which may
    # belong to another device group on this machine.
    Stop-AgentProcesses
    [void](Remove-AgentServices)
    Remove-AgentFirewallRule
    Remove-AgentStateFiles
    Remove-LegacyPayloadFolder
    Write-Log 'uninstall completed'
    return 0
}

# -------------------------------------------------------------------- main ---

Write-Log ('==== agent service helper: mode={0} service={1} group={2} user={3} computer={4} ====' -f $Mode, $ServiceName, $DisplayName, $env:USERNAME, $env:COMPUTERNAME)

try {
    if ($Mode -eq 'uninstall') {
        $result = Invoke-UninstallMode
    } else {
        $result = Invoke-InstallMode
    }
} catch {
    Write-Log ('unhandled error: {0}' -f $_.Exception.Message)
    Write-Log ('at: {0}' -f $_.InvocationInfo.PositionMessage)
    $result = 1
}

exit $result
