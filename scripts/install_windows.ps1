<#
.SYNOPSIS
  One-time setup of the DSC Signer web app on Windows 10/11.

.DESCRIPTION
  1. (optional) installs Python 3.11, cloudflared and NSSM with winget
  2. creates .venv and installs requirements.txt
  3. creates .env from .env.example, generates SECRET_KEY, asks for the first admin
     password and the USB token PIN (typed hidden, written only to .env)
  4. restricts .env permissions to Administrators, SYSTEM and you
  5. checks that the ePass 2003 PKCS#11 driver is installed

.EXAMPLE
  # From an *Administrator* PowerShell in the project folder:
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\scripts\install_windows.ps1

.EXAMPLE
  .\scripts\install_windows.ps1 -SkipWinget      # prerequisites already installed
#>
[CmdletBinding()]
param(
    [switch]$SkipWinget,
    [switch]$SkipSecrets
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
Write-Host "Project folder: $Root" -ForegroundColor Cyan

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ------------------------------------------------------------------ 1. prerequisites
if (-not $SkipWinget) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget not found. See INSTALL.md step 2 (App Installer), or re-run with -SkipWinget."
    }
    if (-not (Test-Admin)) {
        throw "Run this script from an Administrator PowerShell (needed for machine-wide installs)."
    }
    # Python machine-wide (C:\Program Files) so the Windows service can always reach it
    $packages = @(
        @{ Id = 'Python.Python.3.11'; Extra = @('--scope', 'machine', '--override', '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1') },
        @{ Id = 'Cloudflare.cloudflared'; Extra = @() },
        @{ Id = 'NSSM.NSSM'; Extra = @() }
    )
    foreach ($p in $packages) {
        $pkg = $p.Id
        Write-Host "winget: $pkg" -ForegroundColor Cyan
        winget install --id $pkg -e --silent --accept-package-agreements --accept-source-agreements @($p.Extra)
        if ($LASTEXITCODE -ne 0) {
            # -1978335189 = already installed / no newer version
            Write-Host "  (winget exit code $LASTEXITCODE - usually means it is already installed)" -ForegroundColor DarkGray
        }
    }
    # pick up PATH changes made by the installers
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}

# ------------------------------------------------------------------ 2. python + venv
function Find-Python {
    # 1) well-known install folders (3.11 first: the version this app is tested on)
    $known = @(
        "$env:ProgramFiles\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:ProgramFiles\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"
    )
    foreach ($c in $known) {
        if (Test-Path $c) { return $c }
    }
    # 2) ask the py launcher. A missing version makes py write to stderr, which Windows
    #    PowerShell 5.1 turns into a terminating error under 'Stop', so relax it here.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $oldPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            foreach ($v in @('3.11', '3.12', '3.13')) {
                try {
                    $p = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
                    if ($LASTEXITCODE -eq 0 -and $p) {
                        $p = ($p | Select-Object -Last 1).Trim()
                        if ((Test-Path $p) -and ($p -notlike '*WindowsApps*')) { return $p }
                    }
                } catch { }
            }
        } finally {
            $ErrorActionPreference = $oldPref
        }
    }
    return $null
}

$Python = Find-Python
if (-not $Python) { throw "Python 3.11+ not found. Install it: winget install Python.Python.3.11" }
Write-Host "Using Python: $Python" -ForegroundColor Cyan

$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $VenvPy)) {
    & $Python -m venv (Join-Path $Root '.venv')
    if ($LASTEXITCODE -ne 0) { throw "Failed to create virtual environment" }
}
& $VenvPy -m pip install --upgrade pip
& $VenvPy -m pip install -r (Join-Path $Root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

foreach ($d in @('uploads', 'signed', 'data', 'logs')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null
}

# ------------------------------------------------------------------ 3. .env
$EnvFile = Join-Path $Root '.env'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Set-EnvValue([string[]]$Lines, [string]$Key, [string]$Value) {
    # single quotes = literal value for python-dotenv (no escape processing)
    if ($Value.Contains("'")) { throw "$Key cannot contain a single quote ('). Edit .env by hand and use double quotes." }
    $found = $false
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $Lines) {
        if ($l -match "^\s*$([regex]::Escape($Key))\s*=") { $found = $true; $out.Add("$Key='$Value'") } else { $out.Add($l) }
    }
    if (-not $found) { $out.Add("$Key='$Value'") }
    return , $out.ToArray()
}

function Get-EnvValue([string[]]$Lines, [string]$Key) {
    foreach ($l in $Lines) {
        if ($l -match "^\s*$([regex]::Escape($Key))\s*=\s*'?([^']*)'?\s*$") { return $Matches[1] }
    }
    return ''
}

function Read-Secret([string]$Prompt) {
    $sec = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $Root '.env.example') $EnvFile
    Write-Host "Created .env from .env.example" -ForegroundColor Green
}
$lines = [IO.File]::ReadAllLines($EnvFile)

if (-not (Get-EnvValue $lines 'SECRET_KEY')) {
    $key = & $VenvPy -c "import secrets; print(secrets.token_hex(32))"
    $lines = Set-EnvValue $lines 'SECRET_KEY' $key.Trim()
    Write-Host "Generated SECRET_KEY" -ForegroundColor Green
}

if (-not $SkipSecrets) {
    $dbFile = Join-Path $Root 'data\dsc_signer.db'
    if (-not (Test-Path $dbFile) -and -not (Get-EnvValue $lines 'INITIAL_ADMIN_PASS')) {
        $adminUser = Read-Host "First admin username [admin]"
        if (-not $adminUser) { $adminUser = 'admin' }
        do {
            $p1 = Read-Secret "Password for '$adminUser' (min 8 chars)"
            $p2 = Read-Secret "Repeat password"
            if ($p1 -ne $p2) { Write-Warning "Passwords differ" }
            elseif ($p1.Length -lt 8) { Write-Warning "Too short" }
        } while ($p1 -ne $p2 -or $p1.Length -lt 8)
        $lines = Set-EnvValue $lines 'INITIAL_ADMIN_USER' $adminUser
        $lines = Set-EnvValue $lines 'INITIAL_ADMIN_PASS' $p1
    }
    if (-not (Get-EnvValue $lines 'TOKEN_PIN')) {
        Write-Host ""
        Write-Host "The USB token PIN is stored ONLY in .env on this machine." -ForegroundColor Yellow
        Write-Host "Type it carefully: the token locks after several wrong PINs. Leave empty to set later." -ForegroundColor Yellow
        $pin = Read-Secret "ePass 2003 user PIN"
        if ($pin) { $lines = Set-EnvValue $lines 'TOKEN_PIN' $pin }
    }
}
[IO.File]::WriteAllLines($EnvFile, $lines, $Utf8NoBom)

# ------------------------------------------------------------------ 4. lock down .env
try {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    icacls $EnvFile /inheritance:r /grant:r "*S-1-5-32-544:(F)" "*S-1-5-18:(F)" "${me}:(F)" | Out-Null
    Write-Host ".env readable only by Administrators, SYSTEM and $me" -ForegroundColor Green
} catch {
    Write-Warning "Could not restrict .env permissions: $_"
}

# ------------------------------------------------------------------ 5. driver check
$dll = Get-EnvValue $lines 'PKCS11_LIB_PATH'
if (-not $dll) { $dll = 'C:\Windows\System32\eps2003csp11.dll' }
Write-Host ""
if (Test-Path $dll) {
    Write-Host "ePass 2003 PKCS#11 driver found: $dll" -ForegroundColor Green
    Write-Host "Plug in the token and run:  .venv\Scripts\python.exe scripts\list_token.py" -ForegroundColor Cyan
} else {
    Write-Warning "PKCS#11 driver NOT found at $dll. Install the ePass 2003 driver (README section 2)."
}

Write-Host ""
Write-Host "Setup complete. Quick test run:" -ForegroundColor Green
Write-Host "  .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1"
Write-Host "Then open http://127.0.0.1:8000 . Install the service with scripts\install_service.ps1"
