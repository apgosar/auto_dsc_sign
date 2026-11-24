# Fresh install on the DSC machine (bare Windows 10/11)

This guide sets up the Windows PC that holds the **ePass 2003 USB token**, starting from a
fresh Windows install with nothing on it. Run every command in the same
**Administrator PowerShell** window unless a step says otherwise. Allow about 30 minutes.

**You need:**

* Windows 10 (21H2 or later) or Windows 11, **64-bit**, with an administrator account
* Internet access
* The ePass 2003 token, its **user PIN**, and the driver download link from your DSC provider
* Only for access from outside your network: a domain on Cloudflare (free plan is fine). Users
  on the same office or home network don't need this (Step 11A).
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

## Step 4: Install the token driver

1. Download the Windows driver for **your token model** from your DSC provider's support page
   (eMudhra, Capricorn, Sify, (n)Code, VSign, Pantasign, ...). Use the official vendor site
   only. Tokens that look alike use different drivers: Feitian **ePass 2003** and Hypersecu
   **HYP2003** (HyperPKI) are separate downloads.
2. Run the installer as Administrator and accept the defaults.
3. **Unplug the token and plug it back in.**

Find the driver's 64-bit PKCS#11 DLL. You'll set its path as `PKCS11_LIB_PATH` in Step 6.

```powershell
Get-ChildItem C:\Windows\System32, 'C:\Program Files', 'C:\Program Files (x86)' -Recurse -Include *pkcs11*.dll,*csp11*.dll,*p11*.dll -ErrorAction SilentlyContinue | Select-Object FullName, Length
```

Common names:

| Token | 64-bit PKCS#11 DLL |
|---|---|
| Feitian ePass 2003 | `C:\Windows\System32\eps2003csp11.dll` (newer drivers: `eps2003csp11v2.dll`) |
| Hypersecu HYP2003 (HyperPKI) | `C:\Windows\System32\HYP2003csp11IND.dll` |

Use the file in **System32**, never the copy in `SysWOW64` (that one is 32-bit and won't load).
Ignore Git's, Office's and Acrobat's own `*p11*` files. If the list is unclear, this shows
which token software is installed:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -match 'ePass|Feitian|HyperPKI|Hypersecu|Longmai|Watchdata|mToken|SafeNet|Token' } | Select-Object DisplayName, Publisher
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
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 -SkipWinget
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

* `PKCS11_LIB_PATH`: set it to the DLL from Step 4, e.g.
  `PKCS11_LIB_PATH=C:\Windows\System32\HYP2003csp11IND.dll` for a HYP2003 token
* `TOKEN_LABEL`: leave it **blank** for now (the app then uses the token that is plugged in);
  Step 7 shows the real label if you want to pin it
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
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1
```

You should see the `DSCSigner` service *Running* and `Health check OK`. Open
<http://127.0.0.1:8000> again and check that the badge is still green.

**Badge red with `NO_TOKEN` under the service** (but green in Step 8)? Run the service as your
own Windows account instead; it asks for your Windows password:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1 -RunAsUser
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

## Step 10: When the app is available

No power settings need changing. The `DSCSigner` service starts automatically whenever the
laptop is switched on (Windows starts it at boot, before anyone logs in), so the app is
available whenever the laptop is on and the token is plugged in.

* While the laptop is off or asleep, users can't open the app.
* After the laptop wakes up, or the token is plugged back in, the app reconnects to the token
  by itself within about 15 seconds. Documents that were waiting in the queue are then signed.
* The green/red badge at the top of the page shows whether the token is ready.

## Step 11: Let other people reach the app

Pick **one**:

* **11A: Same office or home network only.** No domain, no Cloudflare, nothing to buy. Users
  open the app at `https://<DSC-PC-name>:8000` from their own PCs on the same network.
* **11B: From anywhere (internet).** Uses a Cloudflare Tunnel and a domain whose DNS is on
  Cloudflare.

### Step 11A: Share on the local network (LAN)

1. Give the DSC PC a fixed address so users' bookmarks keep working. In your router's admin
   page, add a **DHCP reservation** (sometimes called "static lease") for this PC. Or simply use
   the PC's name (shown by the next command) instead of an IP address.

   ```powershell
   $env:COMPUTERNAME
   ```

2. Create the HTTPS certificate. HTTPS is needed so passwords aren't sent in plain text across
   the network and so the login cookie works:

   ```powershell
   .venv\Scripts\python.exe scripts\make_lan_cert.py
   ```

   It prints two lines starting with `SSL_CERTFILE=` and `SSL_KEYFILE=`.

3. Open `.env` and set these lines (the two SSL lines are the ones the script printed):

   ```powershell
   notepad C:\dsc-signer\.env
   ```

   ```ini
   HOST=0.0.0.0
   PORT=8000
   SSL_CERTFILE=C:\dsc-signer\certs\server.crt
   SSL_KEYFILE=C:\dsc-signer\certs\server.key
   COOKIE_SECURE=true
   ```

4. Re-run the service installer. It switches the service to the network address, turns on
   HTTPS, opens TCP port 8000 in Windows Firewall (Private and Domain networks only), and prints
   the addresses users should open:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1
   ```

   If it warns that the network is **Public**, other PCs can't connect yet. On your own office
   or home network, mark it Private (use the interface name the warning shows):

   ```powershell
   Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi' -NetworkCategory Private
   ```

5. On another PC on the same network, open `https://<DSC-PC-name>:8000` (or
   `https://<its-IP>:8000`). The browser warns that the connection isn't private, because the
   certificate is self-made. Click **Advanced → Continue**. To make the warning disappear for
   good, copy `C:\dsc-signer\certs\server.crt` to each user's PC and run this there in an
   Administrator PowerShell:

   ```powershell
   Import-Certificate -FilePath .\server.crt -CertStoreLocation Cert:\LocalMachine\Root
   ```

   Then restart that browser. Copy only `server.crt`; never copy `server.key`.

6. In the Admin Panel (Step 12), whitelist your network, e.g. `192.168.1.0/24`, and turn on
   **Enforce whitelist**, so only PCs on your network can even see the login page.

If the PC's IP address changes, re-run `make_lan_cert.py` and `install_service.ps1` (or use the
PC name, which doesn't change). Skip Step 11B.

### Step 11B: Publish it with a Cloudflare Tunnel

Keep `HOST=127.0.0.1` in `.env` for this option: cloudflared connects from the same PC, and
nothing is opened on the local network.

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
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1 -Uninstall
```

```powershell
cloudflared.exe service uninstall
```

Then delete `C:\dsc-signer`, and remove the tunnel in the Cloudflare dashboard.

## If something goes wrong

| Symptom | What to do |
|---|---|
| `running scripts is disabled on this system` | Being Administrator doesn't lift this. Start the script as `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<script>.ps1`. If you downloaded a ZIP, also run `Get-ChildItem C:\dsc-signer -Recurse \| Unblock-File`. Still blocked? `Get-ExecutionPolicy -List` shows whether a Group Policy enforces it |
| `py` not found after Step 3 | Close and reopen the Administrator PowerShell |
| `pip install` fails | Check internet or proxy, then re-run Step 6 |
| Badge `NO_DRIVER` | Driver not installed, or wrong `PKCS11_LIB_PATH` (Step 4) |
| Badge `NO_TOKEN` | Replug the token, run `list_token.py`, try `install_service.ps1 -RunAsUser` |
| Badge `PIN_ERROR` | Fix `TOKEN_PIN` in `.env`, then `Restart-Service DSCSigner` |
| Remote URL shows a Cloudflare error 1033/502 | `Get-Service cloudflared, DSCSigner`. Both must be *Running*; the tunnel URL must be `127.0.0.1:8000` |
| Other PCs on the network can't open the app | Check `.env` has `HOST=0.0.0.0`, re-run `install_service.ps1`, make sure the network is Private (Step 11A.4), and use `https://` |
| Login keeps returning to the login page | Use the `https://` tunnel URL or `http://127.0.0.1:8000`, not the PC's LAN IP |

More detail: [README.md](README.md), sections 2, 5, 6 and 11.
