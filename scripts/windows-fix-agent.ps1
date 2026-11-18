# ============================================================================
# Ex Softwares RMM Agent - one-shot fix + diagnosis
# ============================================================================
# Run this on the Windows machine that should appear in the dashboard.
# It does four things, in order, and writes a report you can send back:
#
#   1. CHECKS that this machine can reach the agent endpoint
#      (remote.hackertreats.com:443, TLS, /meshagents returns the agent).
#   2. CATCHES a proxy/VPN/AV that is intercepting the connection - the PC's
#      proxy settings are compared against a direct connection, which is what
#      explains ERR_TUNNEL_CONNECTION_FAILED in the browser.
#   3. REMOVES every leftover of an earlier install - including the agent
#      service ("ExSoftwaresAgent" for this build, "MeshAgent" for an
#      unbranded one) and the "%ProgramFiles%\Mesh Agent" copy that
#      `-fullinstall` creates. A leftover service pointing at a deleted file
#      is what makes a reinstall "succeed" with no agent running.
#   4. INSTALLS the MSI from a local copy in C:\Windows\Temp (running an MSI
#      straight out of a Downloads folder is the usual cause of the
#      "error 2502/2503" (2xxx) the first attempt showed) with a verbose
#      Windows Installer log.
#   5. VERIFIES the result: service state, the agent's own install log, the
#      registry mesh id, and whether the machine now holds an outbound
#      connection to the server.
#
# Usage (elevated PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\windows-fix-agent.ps1
#   powershell -ExecutionPolicy Bypass -File .\windows-fix-agent.ps1 -MsiPath "C:\Users\you\Downloads\ex-softwares-setup.msi"
#
# The report is written next to the script and to the Desktop.
# ============================================================================

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$MsiPath,
    [string]$Server = 'remote.hackertreats.com',
    [string]$MeshId = 'mesh//n3H@g6XqfaHcCVG7PXjhrvJ0O6o@EwOIGVS$9bKZ9zW8@eFC4JNss1lgLmqmdrZD',
    [string]$ExpectedIp = '13.60.218.175'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop = [Environment]::GetFolderPath('Desktop')
$reportPath = Join-Path $desktop "ex-softwares-agent-report-$stamp.txt"
$lines = New-Object System.Collections.Generic.List[string]

function Say([string]$text, [string]$color = 'Gray') {
    Write-Host $text -ForegroundColor $color
    $lines.Add($text)
}

function Section([string]$title) {
    Say ''
    Say ("== $title ==") 'Cyan'
}

# ---------------------------------------------------------------- helpers ---

function Test-AgentEndpoint {
    param([string]$HostName)

    $out = [ordered]@{ Dns = ''; Tcp443 = ''; Tls = ''; MeshAgents = ''; AgentWs = ''; Detail = '' }

    try {
        $ips = [System.Net.Dns]::GetHostAddresses($HostName) | ForEach-Object { $_.IPAddressToString }
        $out.Dns = ($ips -join ', ')
    } catch {
        $out.Dns = "FAILED: $($_.Exception.Message)"
        return [pscustomobject]$out
    }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, 443, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(8000)) { throw 'connect timed out after 8s' }
        $client.EndConnect($iar)
        $out.Tcp443 = 'open'
    } catch {
        $out.Tcp443 = "FAILED: $($_.Exception.Message)"
        $client.Close()
        return [pscustomobject]$out
    }

    try {
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, { param($s, $c, $ch, $e) $true })
        $ssl.AuthenticateAsClient($HostName)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $out.Tls = "ok, cert CN=$($cert.GetNameInfo('SimpleName', $false)), expires $($cert.NotAfter.ToString('yyyy-MM-dd'))"
        $ssl.Dispose()
    } catch {
        $out.Tls = "FAILED: $($_.Exception.Message)"
    }
    $client.Close()

    # /meshagents is what the portal uses to bake the mesh id into the agent.
    try {
        $url = "https://$HostName/meshagents?id=4&meshid=" + [uri]::EscapeDataString(($MeshId -split '//')[-1])
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30
        $out.MeshAgents = "HTTP $($resp.StatusCode), $($resp.RawContentLength) bytes"
    } catch {
        $out.MeshAgents = "FAILED: $($_.Exception.Message)"
    }

    # The agent itself speaks WebSocket to /agent.ashx. A completed handshake
    # proves the exact path the service will use (not just the web page).
    $ws = $null
    try {
        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        # The agent does not use the system proxy, so probe the same way.
        $ws.Options.Proxy = $null
        $cts = New-Object System.Threading.CancellationTokenSource
        $cts.CancelAfter(10000)
        $task = $ws.ConnectAsync([uri]"wss://$HostName/agent.ashx", $cts.Token)
        if (-not $task.Wait(12000)) { throw 'handshake timed out after 10s' }
        $out.AgentWs = "connected, state=$($ws.State)"
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $out.AgentWs = "FAILED: $($e.Message)"
    } finally {
        if ($ws) { try { $ws.Dispose() } catch { } }
    }

    [pscustomobject]$out
}

function Invoke-Probe {
    # One HTTPS request with the system proxy, one straight out of the NIC.
    # Comparing the two is what separates "the site is down" from
    # "something on this PC is intercepting the connection".
    param([string]$Url, [switch]$Direct)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'HEAD'
        $req.Timeout = 15000
        $req.AllowAutoRedirect = $false
        $req.UserAgent = 'Ex Softwares LLC-AgentCheck/1.0'
        if ($Direct) { $req.Proxy = $null }
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return "HTTP $code"
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        return "FAILED: $($e.Message)"
    }
}

function Get-InterceptionState {
    param([string]$HostName)
    $o = [ordered]@{}

    # WinHTTP - used by services/SYSTEM context.
    $nh = (& netsh winhttp show proxy 2>&1 | Out-String)
    $o.WinHttp = if ($nh -match 'Direct access') { 'direct (no proxy)' }
                 elseif ([string]::IsNullOrWhiteSpace($nh)) { 'unknown (netsh unavailable)' }
                 else { ($nh -replace '\s+', ' ').Trim() }

    # WinINET - used by the browser (this is where ERR_TUNNEL_CONNECTION_FAILED comes from).
    try {
        $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $o.WinInet = "ProxyEnable=$($ie.ProxyEnable)  ProxyServer=$($ie.ProxyServer)  AutoConfigURL=$($ie.AutoConfigURL)  AutoDetect=$($ie.AutoDetect)"
    } catch { $o.WinInet = 'unreadable' }

    $o.EnvProxy = (@('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY') |
        ForEach-Object { "$_=$([Environment]::GetEnvironmentVariable($_))" }) -join '  '

    # VPN / tunnel / packet-filter drivers present as adapters.
    $pattern = 'VPN|TAP|TUN|WireGuard|Wintun|OpenVPN|AnyConnect|GlobalProtect|Fortinet|Sangfor|Psiphon|Shadowsocks|Clash|V2Ray|Nord|Surfshark|Proton|Cloudflare|Zscaler'
    $vpn = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match $pattern }
    $o.VpnAdapters = if ($vpn) { ($vpn | ForEach-Object { "$($_.Name) [$($_.InterfaceDescription)]" }) -join '; ' } else { 'none up' }

    $allUp = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    $o.AdaptersUp = if ($allUp) { ($allUp | ForEach-Object { "$($_.Name) [$($_.InterfaceDescription)]" }) -join '; ' } else { 'unknown' }

    $hostsFile = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    $hit = Select-String -Path $hostsFile -Pattern 'exsoftwares' -ErrorAction SilentlyContinue
    $o.HostsFile = if ($hit) { ($hit.Line -join ' | ') } else { 'no exsoftwares entries' }

    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ',')" }
    $o.DnsServers = if ($dns) { $dns -join ' | ' } else { 'unknown' }

    $o.DirectProbe = Invoke-Probe -Url "https://$HostName/" -Direct
    $o.SystemProbe = Invoke-Probe -Url "https://$HostName/"

    [pscustomobject]$o
}

function Remove-AgentLeftovers {
    # Processes
    Get-Process -Name 'ex-softwares-agent', 'ex-softwares-agent-svc', 'MeshAgent', 'ExSoftwaresAgent' -ErrorAction SilentlyContinue |
        ForEach-Object {
            Say ("  stopping process  {0} (pid {1})" -f $_.ProcessName, $_.Id) 'DarkYellow'
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }

    # Services: the agent's own service ("ExSoftwaresAgent" for this build,
    # "MeshAgent" for an unbranded one), plus anything left pointing into
    # \Mesh Agent\ or \ExSoftwares\Agent\ (even if the file is gone).
    $patterns = @('*ex-softwares-agent*.exe*', '*\Mesh Agent\*.exe*', '*\ExSoftwares\Agent\*.exe*')
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $p = $_.PathName
            @('MeshAgent', 'ExSoftwaresAgent') -contains $_.Name -or ($p -and ($patterns | Where-Object { $p -like $_ }))
        } |
        ForEach-Object {
            Say ("  stopping service  {0}  ({1})" -f $_.Name, $_.PathName) 'DarkYellow'
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            & sc.exe delete "$($_.Name)" | Out-Null
            Say ("  deleted service   {0}" -f $_.Name)
        }

    foreach ($task in @('MeshAgent', 'Ex Softwares Agent')) {
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Say ("  removed scheduled task  {0}" -f $task)
        }
    }

    # Installer registrations owned by this product only.
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -like 'Ex Softwares RMM Agent*') {
                $code = $_.PSChildName
                if ($code -match '^\{[0-9A-Fa-f\-]{36}\}$') {
                    Say ("  uninstalling stale product  {0}  ({1})" -f $p.DisplayName, $code) 'DarkYellow'
                    $p2 = Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait -PassThru
                    Say ("  msiexec /x exit code: {0}" -f $p2.ExitCode)
                }
            }
        }
    }

    # Folders and registry leftovers.
    foreach ($dir in @(
            "$env:ProgramFiles\ExSoftwares",
            "${env:ProgramFiles(x86)}\ExSoftwares",
            "$env:ProgramFiles\Mesh Agent",
            "${env:ProgramFiles(x86)}\Mesh Agent"
        )) {
        if ($dir -and (Test-Path $dir)) {
            Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            Say ("  removed folder  {0}" -f $dir)
        }
    }
    if (Test-Path 'HKLM:\SOFTWARE\Ex Softwares LLC') {
        Remove-Item 'HKLM:\SOFTWARE\Ex Softwares LLC' -Recurse -Force -ErrorAction SilentlyContinue
        Say '  removed HKLM\SOFTWARE\Ex Softwares LLC'
    }
}

function Find-Msi {
    if ($MsiPath) {
        if (-not (Test-Path $MsiPath)) { throw "MSI not found: $MsiPath" }
        return (Resolve-Path $MsiPath).Path
    }
    $candidates = @()
    foreach ($dir in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE")) {
        if (Test-Path $dir) {
            $candidates += Get-ChildItem -Path $dir -Filter '*-setup*.msi' -ErrorAction SilentlyContinue
        }
    }
    $pick = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $pick) { throw 'No *-setup*.msi found in Downloads/Desktop. Pass -MsiPath.' }
    return $pick.FullName
}

# --------------------------------------------------------------- DNS fix ---

function Resolve-PublicDns {
    # Ask a DoH resolver directly: this bypasses the (possibly stale) local
    # resolver cache that made the PC connect to the old server address.
    param([string]$Name, [string]$Endpoint)
    $resp = Invoke-RestMethod -Uri ("$Endpoint`?name=$Name&type=A") -Headers @{ accept = 'application/dns-json' } -TimeoutSec 15 -ErrorAction Stop
    return @($resp.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data })
}

function Get-SystemIps {
    param([string]$Name)
    try {
        return (@([System.Net.Dns]::GetHostAddresses($Name) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString }) -join ', ')
    } catch {
        return "FAILED: $($_.Exception.Message)"
    }
}

function Repair-Dns {
    # A stale A record (typically the address the server had before it was
    # migrated) makes every later step - portal, /meshagents, the agent's own
    # wss:// handshake - fail with a connection timeout. Flush first, and if the
    # answer is still wrong, pin the current address in the hosts file so the
    # install and the service both resolve correctly regardless of the local
    # resolver.
    param([string]$Name, [string]$FallbackIp)

    $out = [ordered]@{ SystemBefore = ''; Public = ''; Flushed = $false; HostsEntry = $false; SystemAfter = '' }
    $out.SystemBefore = Get-SystemIps -Name $Name

    $answers = @()
    foreach ($endpoint in @('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve')) {
        try { $answers += Resolve-PublicDns -Name $Name -Endpoint $endpoint } catch { }
    }
    $answers = @($answers | Select-Object -Unique)
    $out.Public = if ($answers.Count) { $answers -join ', ' } else { 'unavailable' }
    $truth = if ($answers.Count) { $answers[0] } else { $FallbackIp }

    $ok = ($out.SystemBefore -split ',\s*') -contains $truth
    if (-not $ok) {
        ipconfig /flushdns | Out-Null
        $out.Flushed = $true
        Start-Sleep -Seconds 1
        $out.SystemAfter = Get-SystemIps -Name $Name
        $ok = ($out.SystemAfter -split ',\s*') -contains $truth
    } else {
        $out.SystemAfter = $out.SystemBefore
    }

    if (-not $ok -and $truth) {
        $hosts = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
        Copy-Item -Path $hosts -Destination "$hosts.bak-$stamp" -Force -ErrorAction SilentlyContinue
        $kept = @(Get-Content -Path $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '(?i)exsoftwares' })
        $kept += "$truth`t$Name"
        Set-Content -Path $hosts -Value $kept -Encoding ASCII
        ipconfig /flushdns | Out-Null
        $out.HostsEntry = $true
        $out.SystemAfter = Get-SystemIps -Name $Name
    }

    [pscustomobject]$out
}

# ------------------------------------------------------------------ start ---

Say "Ex Softwares RMM agent fix-up - $stamp"
Say "Computer: $env:COMPUTERNAME   User: $env:USERNAME"
Say ("OS: " + (Get-CimInstance Win32_OperatingSystem).Caption)

Section '0. DNS for the agent endpoint'
$dns = Repair-Dns -Name $Server -FallbackIp $ExpectedIp
Say ("  this PC resolved  : {0}" -f $dns.SystemBefore)
Say ("  public resolvers  : {0}" -f $dns.Public)
Say ("  DNS cache flushed : {0}" -f $dns.Flushed)
Say ("  hosts entry added : {0}" -f $dns.HostsEntry)
Say ("  resolves to now   : {0}" -f $dns.SystemAfter)
if ($dns.HostsEntry) {
    Say '  (stale DNS - the address is now pinned in the hosts file)' 'Yellow'
}

Section '1. Reaching the agent endpoint'
$endpoint = Test-AgentEndpoint -HostName $Server
Say ("  DNS        : {0}" -f $endpoint.Dns)
Say ("  TCP 443    : {0}" -f $endpoint.Tcp443)
Say ("  TLS        : {0}" -f $endpoint.Tls)
Say ("  /meshagents: {0}" -f $endpoint.MeshAgents)
Say ("  /agent.ashx: {0}" -f $endpoint.AgentWs)

$networkOk = ($endpoint.Tcp443 -eq 'open') -and ($endpoint.MeshAgents -like 'HTTP 200*')
if (-not $networkOk) {
    Say ''
    Say 'This machine cannot download the per-device agent, so no install can work.' 'Red'
    Say 'Fix DNS/proxy/firewall for remote.hackertreats.com:443 first, then re-run.' 'Red'
}

Section '2. Proxy / VPN / interception on this PC'
$net = Get-InterceptionState -HostName $Server
Say ("  WinHTTP proxy    : {0}" -f $net.WinHttp)
Say ("  Browser (WinINET): {0}" -f $net.WinInet)
Say ("  *_PROXY env vars : {0}" -f $net.EnvProxy)
Say ("  VPN/tunnel NICs  : {0}" -f $net.VpnAdapters)
Say ("  Adapters up      : {0}" -f $net.AdaptersUp)
Say ("  hosts file       : {0}" -f $net.HostsFile)
Say ("  DNS servers      : {0}" -f $net.DnsServers)
Say ("  direct HTTPS     : {0}" -f $net.DirectProbe)
Say ("  via system proxy : {0}" -f $net.SystemProbe)

if ($net.SystemProbe -like 'FAILED*' -and $net.DirectProbe -like 'HTTP*') {
    Say ''
    Say 'VERDICT: the site answers fine when contacted directly, but fails through' 'Red'
    Say 'the proxy/VPN this PC is configured to use. That is what produces' 'Red'
    Say 'ERR_TUNNEL_CONNECTION_FAILED in the browser and blocks the download.' 'Red'
    Say 'Turn the proxy/VPN/AV web-shield off (or add a bypass for' 'Red'
    Say "*.hackertreats.com) and re-run this script." 'Red'
} elseif ($net.SystemProbe -like 'FAILED*' -and $net.DirectProbe -like 'FAILED*') {
    Say ''
    Say 'VERDICT: this PC cannot reach the server by any route - check the local' 'Red'
    Say 'firewall, DNS and the ISP/network in use, then re-run.' 'Red'
}

Section '3. Removing leftovers of earlier installs'
Remove-AgentLeftovers

$msi = $null
try { $msi = Find-Msi } catch { Say ("  " + $_.Exception.Message) 'Red' }

if ($msi) {
    Section '4. Installing the agent MSI'
    $sha = (Get-FileHash -Path $msi -Algorithm SHA256).Hash
    Say ("  package : {0}" -f $msi)
    Say ("  sha256  : {0}" -f $sha)

    # Running the package from a user profile is what produces the 2xxx
    # (2502/2503) "unexpected error" - SYSTEM cannot always read those paths.
    $staged = Join-Path $env:WINDIR "Temp\ex-softwares-setup.msi"
    Copy-Item -Path $msi -Destination $staged -Force
    $msiLog = Join-Path $env:WINDIR "Temp\ex-softwares-msi-$stamp.log"
    Say ("  staged  : {0}" -f $staged)
    Say ("  log     : {0}" -f $msiLog)

    $msiArgs = "/i `"$staged`" /qn /norestart /l*v `"$msiLog`""
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    Say ("  msiexec exit code: {0}" -f $proc.ExitCode) ($(if ($proc.ExitCode -eq 0) { 'Green' } else { 'Red' }))

    if ($proc.ExitCode -ne 0) {
        Say '  Last MSI log lines:' 'Yellow'
        Get-Content $msiLog -Tail 25 -ErrorAction SilentlyContinue |
            ForEach-Object { Say ("    " + $_) }
    }
}

Section '5. Verifying the installed agent'
# The service is named after the agent's embedded meshServiceName
# ("ExSoftwaresAgent"), while an unbranded agent registers "MeshAgent".
# Look for either one, and fall back to matching the image path so a
# future rename does not make this check silently useless.
$svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {
        @('ExSoftwaresAgent', 'MeshAgent') -contains $_.Name -or ($_.PathName -and $_.PathName -like '*MeshAgent.exe*')
    } | Select-Object -First 1
if ($svc) {
    Say ("  service {0} : state={1} start={2}" -f $svc.Name, $svc.State, $svc.StartMode)
    Say ("  image path        : {0}" -f $svc.PathName)
} else {
    Say '  service           : NOT INSTALLED (looked for ExSoftwaresAgent and MeshAgent)' 'Red'
}

$agentExe = $null
if ($svc -and $svc.PathName) {
    $agentExe = $svc.PathName.Trim('"')
    if ($agentExe -match '^[^\s]+\.exe') { $agentExe = $Matches[0] }
}
$msiAgent = Join-Path $env:ProgramFiles 'ExSoftwares\Agent\ex-softwares-agent.exe'
$meshAgent = Join-Path $env:ProgramFiles 'Mesh Agent\MeshAgent.exe'
if (-not $agentExe -or -not (Test-Path $agentExe)) {
    if (Test-Path $msiAgent) { $agentExe = $msiAgent } else { $agentExe = $meshAgent }
}
if (Test-Path $agentExe) { Say ("  agent binary      : {0}" -f $agentExe) }
else { Say '  agent binary      : missing (neither ExSoftwares\Agent nor Mesh Agent)' 'Red' }

# The agent's own -fullinstall is not idempotent: after a locked self-copy or a
# stale registration it exits 0 without creating anything, and the MSI reports
# success. Register the service directly instead of leaving a dead machine.
if (-not $svc -and (Test-Path $agentExe)) {
    Say ''
    Say '  service missing - registering it directly' 'Yellow'
    $svcName = 'ExSoftwaresAgent'
    $binPath = '"{0}" --meshServiceName="{1}"' -f $agentExe, $svcName
    try {
        New-Service -Name $svcName -BinaryPathName $binPath -DisplayName 'Ex Softwares RMM Agent' -StartupType Automatic -ErrorAction Stop | Out-Null
        Say ("  created service {0}" -f $svcName)
    } catch {
        Say ("  New-Service failed: {0}" -f $_.Exception.Message) 'Red'
        & sc.exe create "$svcName" binPath= "$binPath" start= auto DisplayName= "Ex Softwares RMM Agent" | Out-Null
    }
    & sc.exe description "$svcName" "Ex Softwares LLC remote monitoring and management agent." | Out-Null
    & sc.exe failure "$svcName" reset= 86400 actions= restart/60000/restart/60000/restart/120000 | Out-Null
    & netsh advfirewall firewall delete rule name="Ex Softwares RMM Agent" | Out-Null
    & netsh advfirewall firewall add rule name="Ex Softwares RMM Agent" dir=in action=allow program="$agentExe" enable=yes profile=any | Out-Null
    try { Start-Service -Name $svcName -ErrorAction Stop } catch { & sc.exe start "$svcName" | Out-Null }
    Start-Sleep -Seconds 3
    $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $svcName } | Select-Object -First 1
    if ($svc) {
        Say ("  service {0} : state={1} start={2}" -f $svc.Name, $svc.State, $svc.StartMode) ($(if ($svc.State -eq 'Running') { 'Green' } else { 'Red' }))
    } else {
        Say '  service still missing after direct registration' 'Red'
    }
}

$log = Join-Path $env:ProgramData 'ExSoftwares\agent-install.log'
if (Test-Path $log) {
    Say '  runner log (last install):' 'Yellow'
    Get-Content $log -Tail 12 | ForEach-Object { Say ("    " + $_) }
} else {
    Say '  runner log        : not written' 'Yellow'
}

$reg = Get-ItemProperty 'HKLM:\SOFTWARE\ExSoftwares\Agent' -ErrorAction SilentlyContinue
if ($reg) {
    Say ("  registry MeshId   : {0}" -f $reg.MeshId)
    Say ("  registry Server   : {0}" -f $reg.ServerUrl)
}

$conns = Get-NetTCPConnection -RemotePort 443 -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -ne 0 }
$agentConn = $conns | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($p -and ($p.ProcessName -like '*MeshAgent*' -or $p.ProcessName -like '*ExSoftwaresAgent*')) { $_ }
}
if ($agentConn) {
    Say ("  outbound to server: {0} connection(s) established by the agent" -f @($agentConn).Count) 'Green'
} else {
    Say '  outbound to server: no agent connection yet (it retries every few minutes)' 'Yellow'
}

Section 'Summary'
$ok = $svc -and $svc.State -eq 'Running'
if ($ok) {
    Say 'The agent service is installed and running.' 'Green'
    Say 'Open the dashboard; the device should appear within ~1 minute.' 'Green'
    Say 'If it does not, send this report - sections 1, 2 and 5 show where it stops.' 'Green'
} else {
    Say 'The agent service is NOT running. Send this report back.' 'Red'
}

$lines | Set-Content -Path $reportPath -Encoding UTF8
Write-Host ''
Write-Host ("Report written to {0}" -f $reportPath) -ForegroundColor Cyan
