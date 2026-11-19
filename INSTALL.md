# Fresh install on the DSC machine (bare Windows 10/11)

This guide sets up the Windows PC that holds the **ePass 2003 USB token**, starting from a
fresh Windows install with nothing on it. Run every command in the same
**Administrator PowerShell** window unless a step says otherwise. Allow about 30 minutes.

**You need:**

* Windows 10 (21H2 or later) or Windows 11, **64-bit**, with an administrator account
* Internet access
* The ePass 2003 token, its **user PIN**, and the driver download link from your DSC provider
* A domain on Cloudflare (free plan is fine) for remote access
* Access to the GitHub repo <https://github.com/apgosar/auto_dsc_sign>

The app goes in **`C:\dsc-signer`**. Keep that path: it has no spaces and sits outside any
user profile, so the Windows service can always read it.

---

## Step 1: Open an Administrator PowerShell

Press **Start**, type `powershell`, right-click **Windows PowerShell**, then choose
**Run as administrator** and click **Yes**. The window title should start with
*Administrator:*.

Allow scripts in this window only. Nothing changes system-wide:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

## Step 2: Make sure winget works

```powershell
winget --version
```

If you get a version number (e.g. `v1.9.x`), go to Step 3. If it says *winget is not
recognized*, register the App Installer package:

```powershell
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
```

Close and reopen the Administrator PowerShell, then run `winget --version` again. If it is
still missing, install **App Installer** from the Microsoft Store (or <https://aka.ms/getwinget>)
and reopen PowerShell. Re-run `Set-ExecutionPolicy -Scope Process Bypass -Force` in each new
window.

Accept the winget source agreements once:

```powershell
winget source update --accept-source-agreements
```

## Step 3: Install Git, Python, cloudflared and NSSM

```powershell
winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements
```

```powershell
winget install --id Python.Python.3.11 -e --scope machine --silent --accept-package-agreements --override "/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1"
```

```powershell
winget install --id Cloudflare.cloudflared -e --silent --accept-package-agreements
```

```powershell
winget install --id NSSM.NSSM -e --silent --accept-package-agreements
```

Reload `PATH` in this window so the new programs are found:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
```

Check each one (every command should print a version):

```powershell
git --version
```

```powershell
py -3.11 --version
```

```powershell
cloudflared --version
```

```powershell
nssm version
```

If `nssm` is not found, close and reopen the Administrator PowerShell (and re-run the
`Set-ExecutionPolicy` line). winget registers it through a link that new windows pick up.

> `python` might open the Microsoft Store instead of running Python. Use `py -3.11` as shown,
> or turn off the *python.exe* alias under Settings → Apps → Advanced app settings → App
> execution aliases.

## Step 4: Install the ePass 2003 driver

1. Download the **ePass2003 Windows setup** from your DSC provider's support page (eMudhra,
   Capricorn, Sify, (n)Code, VSign, Pantasign, ...). Use the official vendor site only.
2. Run the installer as Administrator and accept the defaults.
3. **Unplug the token and plug it back in.**

Verify:

```powershell
Test-Path C:\Windows\System32\eps2003csp11.dll
```

It must print `True`. If it prints `False`, find where the installer put the DLL. You'll set
that path as `PKCS11_LIB_PATH` in Step 6.

```powershell
Get-ChildItem C:\Windows\System32, 'C:\Program Files', 'C:\Program Files (x86)' -Recurse -Filter 'eps2003csp11*.dll' -ErrorAction SilentlyContinue | Select-Object FullName
```

Check that Windows sees the token. A PIN prompt may appear: press **Cancel**.

```powershell
certutil -scinfo -silent
```

## Step 5: Download the app code

```powershell
git clone https://github.com/apgosar/auto_dsc_sign.git C:\dsc-signer
```

If the repo is private, a GitHub sign-in window opens. Sign in as `apgosar` (or an account with
access) and the clone continues.

```powershell
Set-Location C:\dsc-signer
```

*No Git?* Download the ZIP instead: on GitHub click **Code → Download ZIP**, extract it, rename
the folder to `C:\dsc-signer`, then run `Set-Location C:\dsc-signer`.

## Step 6: Run the installer

Step 3 already installed the prerequisites, so skip winget:

```powershell
.\scripts\install_windows.ps1 -SkipWinget
```

The script creates `C:\dsc-signer\.venv`, installs the Python packages (a few minutes), and
creates `.env`. It then asks for:

* **First admin username** (press Enter for `admin`) and **password** (min 8 characters, typed
  twice; nothing shows while you type)
* **ePass 2003 user PIN**: type it carefully, because the token locks after a few wrong PINs.
  Press Enter to leave it empty and add it later.

It finishes by checking the driver DLL.

Review the settings:

```powershell
notepad C:\dsc-signer\.env
```

Check these lines and save:

* `PKCS11_LIB_PATH`: change it if Step 4 found the DLL somewhere else
* `TOKEN_LABEL`: set in Step 7 (leave blank to use the first token)
* `SIGN_REASON` / `SIGN_LOCATION`: optional defaults, e.g. `SIGN_LOCATION='Mumbai'`
* `TSA_URL`: optional timestamp server, e.g. `TSA_URL=http://timestamp.digicert.com`

Values containing `#`, spaces or `$` must be in single quotes.

## Step 7: Check the token and certificate

With the token plugged in:

```powershell
.venv\Scripts\python.exe scripts\list_token.py
```

This needs no PIN and can't lock the token. It prints:

* `Token label : '...'`: copy that label into `TOKEN_LABEL` in `.env` (or leave it blank)
* every certificate, with its holder name, issuer, validity dates and usage. The one marked
  **usable for signing** is the one the app will use. If several are marked, put part of the
  wanted holder's name in `CERT_LABEL`.

Then test the PIN once:

```powershell
.venv\Scripts\python.exe scripts\list_token.py --test-login
```

You should see `Login OK`. On `PIN INCORRECT`, fix `TOKEN_PIN` in `.env` **before** trying
again. On `PIN LOCKED`, unlock the token with your provider's ePass2003 Token Manager (needs
the SO PIN) or contact the provider.

## Step 8: Test run on this PC

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Open **<http://127.0.0.1:8000>** in a browser on this PC and sign in with the admin account
from Step 6. The badge at the top right should be green: **Token ready · <certificate name>**.
Upload a small PDF, draw a signature box, click **Queue for signing**, and download the result.
Open the signed file in Adobe Acrobat Reader and check the signature panel.

Go back to PowerShell and press **Ctrl+C** to stop the server.

Remove the bootstrap password: open `.env` in Notepad and blank out `INITIAL_ADMIN_PASS`. The
admin account is already saved in the database.

```powershell
notepad C:\dsc-signer\.env
```

## Step 9: Install the Windows service (auto-start)

```powershell
.\scripts\install_service.ps1
```

You should see the `DSCSigner` service *Running* and `Health check OK`. Open
<http://127.0.0.1:8000> again and check that the badge is still green.

**Badge red with `NO_TOKEN` under the service** (but green in Step 8)? Run the service as your
own Windows account instead; it asks for your Windows password:

```powershell
.\scripts\install_service.ps1 -RunAsUser
```

Service commands for later:

```powershell
Get-Service DSCSigner
```

```powershell
Restart-Service DSCSigner
```

```powershell
Get-Content C:\dsc-signer\logs\app.log -Tail 50 -Wait
```

## Step 10: Keep the PC and the USB port awake

```powershell
powercfg /change standby-timeout-ac 0
```

```powershell
powercfg /change hibernate-timeout-ac 0
```

```powershell
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
```

```powershell
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
```

```powershell
powercfg /SETACTIVE SCHEME_CURRENT
```

These disable sleep, hibernate, the lid-close action (laptops) and USB selective suspend while
on AC power. Keep the PC plugged in. Optionally, in **Device Manager → Universal Serial Bus
controllers → each USB Root Hub → Power Management**, untick *Allow the computer to turn off
this device to save power*.

## Step 11: Publish it with a Cloudflare Tunnel

1. Sign in at <https://dash.cloudflare.com> and open **Zero Trust** (first time: pick a team
   name and the free plan).
2. Go to **Networks → Tunnels → Create a tunnel** → **Cloudflared** → name it `dsc-signer` →
   **Save**.
3. Under *Install and run a connector*, choose **Windows** and copy the command it shows. Run
   it in the Administrator PowerShell. It looks like this (use your own token):

   ```powershell
   cloudflared.exe service install eyJhIjoi...your-long-token...
   ```

4. Back in the dashboard, click **Next**. On **Public Hostname**, enter:
   * **Subdomain:** `sign` · **Domain:** your domain
   * **Type:** `HTTP` · **URL:** `127.0.0.1:8000`

   Then click **Save tunnel**.
5. Check that the connector service is running:

   ```powershell
   Get-Service cloudflared
   ```

6. From a phone or another computer, open `https://sign.<your-domain>` and sign in.

(Optional) For an extra login layer, go to **Zero Trust → Access → Applications → Add an
application → Self-hosted**, enter `sign.<your-domain>`, and add a policy that allows only your
email addresses.

## Step 12: Lock down access in the Admin Panel

Open `https://sign.<your-domain>/admin` (or <http://127.0.0.1:8000/admin> on the PC):

1. **Users → Create new login** for each person who needs to sign. Tick **Lock to first device
   (TOFU)** for remote users.
2. **Global IP whitelist:** add office or home IPs (or CIDR ranges), or click **Whitelist my
   current IP** from each approved location, then switch on **Enforce whitelist**. Visitors
   from other IPs get *403 Access Denied* before the login page. The PC itself (localhost) is
   always allowed, so you can't lock yourself out.
3. Watch the **Access audit log** for blocked attempts. **Approve device** / **Whitelist IP**
   buttons appear on legitimate blocked entries.

Setup is complete.

---

## Updating to a newer version later

```powershell
Set-Location C:\dsc-signer
```

```powershell
git pull
```

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

```powershell
Restart-Service DSCSigner
```

Your `.env`, users and settings (`data\dsc_signer.db`) are kept across updates.

## Uninstalling

```powershell
.\scripts\install_service.ps1 -Uninstall
```

```powershell
cloudflared.exe service uninstall
```

Then delete `C:\dsc-signer`, and remove the tunnel in the Cloudflare dashboard.

## If something goes wrong

| Symptom | What to do |
|---|---|
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process Bypass -Force` in this window first |
| `py` not found after Step 3 | Close and reopen the Administrator PowerShell |
| `pip install` fails | Check internet or proxy, then re-run `.\scripts\install_windows.ps1 -SkipWinget` |
| Badge `NO_DRIVER` | Driver not installed, or wrong `PKCS11_LIB_PATH` (Step 4) |
| Badge `NO_TOKEN` | Replug the token, run `list_token.py`, try `install_service.ps1 -RunAsUser` |
| Badge `PIN_ERROR` | Fix `TOKEN_PIN` in `.env`, then `Restart-Service DSCSigner` |
| Remote URL shows a Cloudflare error 1033/502 | `Get-Service cloudflared, DSCSigner`. Both must be *Running*; the tunnel URL must be `127.0.0.1:8000` |
| Login keeps returning to the login page | Use the `https://` tunnel URL or `http://127.0.0.1:8000`, not the PC's LAN IP |

More detail: [README.md](README.md), sections 2, 5, 6 and 11.
