<#
.SYNOPSIS
  Registers the DSC Signer app as an auto-start Windows Service using NSSM.

.DESCRIPTION
  Runs:  .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port <Port> --workers 1
  ALWAYS a single worker: the USB token queue lives in one process.

  By default the service runs as LocalSystem. If the token is not detected when running
  as a service (some token middleware only works in a user session), re-run with
  -RunAsUser to run it under your Windows account (you will be asked for its password).

.EXAMPLE
  # Administrator PowerShell, project folder:
  .\scripts\install_service.ps1
  .\scripts\install_service.ps1 -RunAsUser
  .\scripts\install_service.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ServiceName = 'DSCSigner',
    [int]$Port = 0,
    [switch]$RunAsUser,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an Administrator PowerShell."
}

function Find-Nssm {
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $hits = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages", "$env:ProgramFiles", "${env:ProgramFiles(x86)}" `
        -Filter nssm.exe -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'win64' }
    if ($hits) { return $hits[0].FullName }
    $hits = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter nssm.exe -Recurse -ErrorAction SilentlyContinue
    if ($hits) { return $hits[0].FullName }
    return $null
}

$Nssm = Find-Nssm
if (-not $Nssm) { throw "nssm.exe not found. Install it: winget install NSSM.NSSM (then open a new PowerShell)" }
Write-Host "NSSM: $Nssm" -ForegroundColor Cyan

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

function Stop-DscService {
    # Ask the service to stop; if it is still running (or stuck in StopPending) after 30 s,
    # end its process tree (nssm.exe + python.exe) so it can be reconfigured and restarted.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Stopped') { return }
    Write-Host "Stopping $ServiceName ..." -ForegroundColor Cyan
    & $Nssm stop $ServiceName 2>&1 | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $svc.Refresh()
        if ($svc.Status -eq 'Stopped') { return }
        Start-Sleep -Seconds 1
    }
    $svcPid = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
    if ($svcPid -and $svcPid -ne 0) {
        Write-Warning "$ServiceName did not stop in time; ending its process (PID $svcPid)."
        & taskkill.exe /PID $svcPid /T /F 2>&1 | Out-Null
    }
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        $svc.Refresh()
        if ($svc.Status -eq 'Stopped') { return }
        Start-Sleep -Seconds 1
    }
    throw "$ServiceName is still $($svc.Status). Restart Windows, then run this script again."
}

if ($Uninstall) {
    if ($existing) {
        Stop-DscService
        & $Nssm remove $ServiceName confirm
        Write-Host "Service $ServiceName removed." -ForegroundColor Green
    } else {
        Write-Host "Service $ServiceName is not installed."
    }
    return
}

$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $VenvPy)) { throw "Virtual environment missing. Run scripts\install_windows.ps1 first." }
if (-not (Test-Path (Join-Path $Root '.env'))) { throw ".env missing. Run scripts\install_windows.ps1 first." }

if ($Port -eq 0) {
    $Port = 8000
    $m = Select-String -Path (Join-Path $Root '.env') -Pattern "^\s*PORT\s*=\s*'?(\d+)" -ErrorAction SilentlyContinue
    if ($m) { $Port = [int]$m.Matches[0].Groups[1].Value }
}

$LogDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if ($existing) {
    Write-Host "Service exists; updating configuration." -ForegroundColor Yellow
    Stop-DscService
} else {
    & $Nssm install $ServiceName $VenvPy
    if ($LASTEXITCODE -ne 0) { throw "nssm install failed" }
}

function Get-DotEnv([string]$Key) {
    $m = Select-String -Path (Join-Path $Root '.env') -Pattern "^\s*$([regex]::Escape($Key))\s*=\s*'?([^'#]*?)'?\s*$" -ErrorAction SilentlyContinue
    if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
    return ''
}

# HOST=127.0.0.1 -> only this PC (e.g. behind a tunnel); HOST=0.0.0.0 -> reachable from the LAN
$HostAddr = Get-DotEnv 'HOST'
if (-not $HostAddr) { $HostAddr = '127.0.0.1' }
$SslCert = Get-DotEnv 'SSL_CERTFILE'
$SslKey = Get-DotEnv 'SSL_KEYFILE'
$UseTls = [bool]($SslCert -and $SslKey)
if ($UseTls) {
    foreach ($f in @($SslCert, $SslKey)) { if (-not (Test-Path $f)) { throw "SSL file not found: $f (see INSTALL.md, LAN setup)" } }
}

$appArgs = "-m uvicorn app.main:app --host $HostAddr --port $Port --workers 1 --no-server-header --timeout-graceful-shutdown 5"
if ($UseTls) { $appArgs += " --ssl-certfile `"$SslCert`" --ssl-keyfile `"$SslKey`"" }
& $Nssm set $ServiceName Application $VenvPy | Out-Null
& $Nssm set $ServiceName AppParameters $appArgs | Out-Null
& $Nssm set $ServiceName AppDirectory $Root | Out-Null
& $Nssm set $ServiceName DisplayName 'DSC Signer (ePass 2003 PDF signing)' | Out-Null
& $Nssm set $ServiceName Description 'Self-hosted PDF digital signing web app using the USB DSC token.' | Out-Null
& $Nssm set $ServiceName Start SERVICE_AUTO_START | Out-Null
& $Nssm set $ServiceName AppStdout (Join-Path $LogDir 'service.log') | Out-Null
& $Nssm set $ServiceName AppStderr (Join-Path $LogDir 'service.log') | Out-Null
& $Nssm set $ServiceName AppRotateFiles 1 | Out-Null
& $Nssm set $ServiceName AppRotateOnline 1 | Out-Null
& $Nssm set $ServiceName AppRotateBytes 5000000 | Out-Null
& $Nssm set $ServiceName AppExit Default Restart | Out-Null
& $Nssm set $ServiceName AppRestartDelay 5000 | Out-Null
& $Nssm set $ServiceName AppStopMethodConsole 10000 | Out-Null
& $Nssm set $ServiceName AppStopMethodWindow 3000 | Out-Null
& $Nssm set $ServiceName AppStopMethodThreads 3000 | Out-Null
& $Nssm set $ServiceName AppKillProcessTree 1 | Out-Null
& $Nssm set $ServiceName AppEnvironmentExtra 'PYTHONUNBUFFERED=1' | Out-Null

if ($RunAsUser) {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $cred = Get-Credential -UserName $user -Message "Windows password for $user (service logon)"
    $plain = $cred.GetNetworkCredential().Password
    & $Nssm set $ServiceName ObjectName $user $plain | Out-Null
    Write-Host "Service will run as $user" -ForegroundColor Cyan
} else {
    & $Nssm set $ServiceName ObjectName LocalSystem | Out-Null
}

# Shared on the LAN: allow the port through Windows Firewall (Private/Domain networks only)
$RuleName = "DSC Signer (TCP $Port)"
if ($HostAddr -ne '127.0.0.1' -and $HostAddr -ne 'localhost') {
    if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
            -Action Allow -Profile Private, Domain | Out-Null
        Write-Host "Firewall: allowed inbound TCP $Port on Private/Domain networks." -ForegroundColor Green
    }
    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.NetworkCategory -eq 'Public' }
    foreach ($p in $profiles) {
        Write-Warning "Network '$($p.Name)' ($($p.InterfaceAlias)) is set to Public, so other PCs can't connect. If it is your office/home network, run:  Set-NetConnectionProfile -InterfaceAlias '$($p.InterfaceAlias)' -NetworkCategory Private"
    }
}

& $Nssm start $ServiceName
Start-Sleep -Seconds 5
Get-Service $ServiceName | Format-Table -AutoSize Name, Status, StartType

$Scheme = if ($UseTls) { 'https' } else { 'http' }
try {
    if ($UseTls) {
        # self-signed certificate: skip validation for this local check only
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    $r = Invoke-WebRequest -UseBasicParsing -Uri "${Scheme}://127.0.0.1:$Port/healthz" -TimeoutSec 10
    Write-Host "Health check OK: $($r.Content)" -ForegroundColor Green
    Write-Host "On this PC:  ${Scheme}://127.0.0.1:$Port"
    if ($HostAddr -ne '127.0.0.1' -and $HostAddr -ne 'localhost') {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' }
        foreach ($ip in $ips) { Write-Host "On the LAN:  ${Scheme}://$($ip.IPAddress):$Port   ($($ip.InterfaceAlias))" -ForegroundColor Cyan }
        Write-Host "             ${Scheme}://$($env:COMPUTERNAME):$Port" -ForegroundColor Cyan
    }
} catch {
    Write-Warning "Health check failed. See $LogDir\service.log and $LogDir\app.log"
}
