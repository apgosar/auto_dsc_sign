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

if ($Uninstall) {
    if ($existing) {
        & $Nssm stop $ServiceName | Out-Null
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
    & $Nssm stop $ServiceName | Out-Null
} else {
    & $Nssm install $ServiceName $VenvPy
    if ($LASTEXITCODE -ne 0) { throw "nssm install failed" }
}

$appArgs = "-m uvicorn app.main:app --host 127.0.0.1 --port $Port --workers 1 --no-server-header"
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
& $Nssm set $ServiceName AppStopMethodConsole 15000 | Out-Null
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

& $Nssm start $ServiceName
Start-Sleep -Seconds 5
Get-Service $ServiceName | Format-Table -AutoSize Name, Status, StartType

try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 10
    Write-Host "Health check OK: $($r.Content)" -ForegroundColor Green
    Write-Host "Open http://127.0.0.1:$Port in a browser on this machine."
} catch {
    Write-Warning "Health check failed. See $LogDir\service.log and $LogDir\app.log"
}
