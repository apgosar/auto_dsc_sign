# DSC Signer: self-hosted PDF signing with an ePass 2003 USB token

A FastAPI web app that runs on the Windows laptop where the **ePass 2003 USB DSC token** is
plugged in. Approved users upload PDFs from anywhere through a **Cloudflare Tunnel**, choose where
the signature goes, and download PAdES-signed PDFs. An **Admin Panel** manages logins, the IP
whitelist and device locks.

```
 Browser ──HTTPS──► Cloudflare ──tunnel──► cloudflared (this laptop) ──► 127.0.0.1:8000 FastAPI
                                                                             │
                                                    queue.Queue ──► ONE worker thread ──► eps2003csp11.dll ──► USB token
```

* The token driver is single-threaded. **Every** PKCS#11 call (login, certificate lookup,
  health checks, signing) runs on one dedicated worker thread fed by `queue.Queue`. Always run
  uvicorn with `--workers 1`; the service script does this for you.
* The token PIN lives only in `.env` on this laptop. Remote users never see it or type it.
* If the token rejects the PIN once, the worker stops trying (the token locks after a few wrong
  PINs). Fix `TOKEN_PIN` and restart the service.

Contents: [1. Prerequisites](#1-prerequisites-winget) · [2. ePass 2003 driver & certificate check](#2-epass-2003-driver--certificate-verification) ·
[3. Install the app](#3-install-the-app) · [4. First run](#4-first-run-local-test) · [5. Windows service (NSSM)](#5-run-as-a-windows-service-nssm) ·
[6. Cloudflare Tunnel](#6-expose-it-with-cloudflare-tunnel) · [7. Keep the laptop awake](#7-keep-the-laptop-and-token-awake) ·
[8. Using the app](#8-using-the-app) · [9. Admin Panel](#9-admin-panel) · [10. Testing without the token](#10-testing-without-the-token) ·
[11. Troubleshooting](#11-troubleshooting) · [12. Security notes](#12-security-notes)

---

## 1. Prerequisites (winget)

Open **PowerShell as Administrator** (Start → type *PowerShell* → *Run as administrator*):

```powershell
winget install --id Python.Python.3.11 -e --scope machine --override "/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1"
winget install --id Cloudflare.cloudflared -e
winget install --id NSSM.NSSM -e
```

> **Setting up a brand-new PC?** Follow [INSTALL.md](INSTALL.md): it goes from a bare Windows
> install to a running, tunnelled service, one command at a time.

Close and reopen PowerShell so the new `PATH` takes effect. Check the installs:

```powershell
py -3.11 --version
cloudflared --version
nssm version
```

> `scripts\install_windows.ps1` (section 3) runs these winget commands for you if you prefer.

---

## 2. ePass 2003 driver & certificate verification

### 2.1 Install the driver

The ePass 2003 middleware comes from your DSC provider (eMudhra, Capricorn, Sify, (n)Code,
VSign, etc.) or from the token maker (Feitian/Longmai). Download the **ePass2003 Windows
setup** from your provider's download page, run it as Administrator, then **unplug and replug
the token**.

The DLL name depends on the token model and driver version, so search for it and set
`PKCS11_LIB_PATH` in `.env` to the 64-bit one:

```powershell
Get-ChildItem C:\Windows\System32, 'C:\Program Files', 'C:\Program Files (x86)' -Recurse -Include *pkcs11*.dll,*csp11*.dll,*p11*.dll -ErrorAction SilentlyContinue | Select-Object FullName, Length
```

| Token | 64-bit PKCS#11 DLL |
|---|---|
| Feitian ePass 2003 | `C:\Windows\System32\eps2003csp11.dll` (newer drivers: `eps2003csp11v2.dll`) |
| Hypersecu HYP2003 (HyperPKI), an ePass 2003-compatible token sold in India | `C:\Windows\System32\HYP2003csp11IND.dll` |

Ignore other programs' `*p11*` files (Git, Office, Acrobat).

> Use the **64-bit** DLL (in `System32`) with 64-bit Python. The 32-bit copy in `SysWOW64`
> will not load.

### 2.2 Check that Windows sees the token

```powershell
Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName -match 'ePass|Feitian|Smart ?card' } | Format-Table Status, Class, FriendlyName
certutil -scinfo -silent
```

`certutil -scinfo` reads the token through the Windows smart-card stack and lists its
certificates. Press **Cancel** if it asks for a PIN; you don't need to enter it here.

### 2.3 List the token and certificates through PKCS#11 (no PIN)

After section 3 (the virtual environment must exist):

```powershell
.venv\Scripts\python.exe scripts\list_token.py
```

This loads the DLL from `PKCS11_LIB_PATH` (or pass `--lib <path>`), prints the **token label** (put it in `TOKEN_LABEL`) and every
certificate with its subject, issuer, validity and key usage. It never logs in, so it cannot
lock the token. A DSC token often holds two certificates: a **signing** one (key usage
`non_repudiation` / `digital_signature`) and an **encryption** one. The app automatically picks
the valid signing certificate that has a private key. If several match, set `CERT_LABEL` to
part of the wanted certificate's label or holder name.

### 2.4 Optional: test the PIN once

```powershell
.venv\Scripts\python.exe scripts\list_token.py --test-login
```

This does **one** login with `TOKEN_PIN` from `.env`. If it says *PIN INCORRECT*, fix the PIN
before trying again. If it says *PIN LOCKED*, unlock the token with your provider's ePass2003
token manager (this needs the SO/admin PIN, or contact your DSC provider).

---

## 3. Install the app

Put the project folder somewhere permanent, e.g. `C:\AnkurGosar\auto_digi_sign`. In an
**Administrator PowerShell** inside that folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

The script:

1. installs Python, cloudflared and NSSM with winget (skip this with `-SkipWinget`)
2. creates `.venv` and installs `requirements.txt`
3. copies `.env.example` to `.env`, generates `SECRET_KEY`, and asks (hidden input) for the
   first admin's username and password and the token PIN
4. makes `.env` readable only by Administrators, SYSTEM and your account
5. checks that the ePass 2003 DLL exists

Then review `.env` in Notepad (`notepad .env`). The settings you'll most likely touch:

| Setting | Meaning |
|---|---|
| `PKCS11_LIB_PATH` | Path to the token's 64-bit PKCS#11 DLL (`eps2003csp11.dll`, `HYP2003csp11IND.dll`, ...) |
| `TOKEN_LABEL` | Token label from `list_token.py`. Leave blank to use the first token found |
| `TOKEN_PIN` | Token user PIN. **Never share or commit this file** |
| `CERT_LABEL` | Optional filter if the token holds several signing certificates |
| `TSA_URL` | Optional RFC 3161 timestamp server, e.g. `http://timestamp.digicert.com` |
| `SIGN_REASON` / `SIGN_LOCATION` | Defaults shown in the upload form |
| `INITIAL_ADMIN_USER` / `INITIAL_ADMIN_PASS` | First admin, created only when the database is empty. **Delete the password from `.env` after the first start** |
| `ENFORCE_GLOBAL_IP_WHITELIST` | Initial state only; after the first start, toggle it in the Admin Panel |
| `FILE_RETENTION_MINUTES` | Uploaded and signed PDFs are deleted after this many minutes (default 60) |
| `ADMIN_LOCALHOST_ONLY` | `true` = Admin Panel only reachable from the laptop itself |

Values with special characters (`#`, spaces, `$`) must be in single quotes: `TOKEN_PIN='12#34'`.
The installer does this automatically.

---

## 4. First run (local test)

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Open <http://127.0.0.1:8000>, sign in with the admin account, and check the badge at the top
right. **Green "Token ready · <your name>"** means the token, PIN and certificate all work. A red
badge shows the reason (driver missing, no token, PIN error...) on hover and in the Admin Panel.

Sign a test PDF before going remote. Then stop the server with **Ctrl+C** and remove
`INITIAL_ADMIN_PASS` from `.env`.

---

## 5. Run as a Windows service (NSSM)

In an **Administrator PowerShell** in the project folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1
```

This registers the **DSCSigner** service (auto-start, restarts on crash after 5 s, logs in
`logs\service.log` and `logs\app.log`) and checks `http://127.0.0.1:8000/healthz`.

If the badge shows **NO_TOKEN** under the service but the token worked in section 4, the
token middleware needs a user session. Run the service as your own Windows account:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1 -RunAsUser
```

Useful commands:

```powershell
Get-Service DSCSigner
Restart-Service DSCSigner
Get-Content .\logs\app.log -Tail 50 -Wait
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_service.ps1 -Uninstall
```

Restart the service after editing `.env`.

---

## 6. Expose it with Cloudflare Tunnel

You need a domain on Cloudflare (free plan is fine). The tunnel makes an outbound connection, so
no router port forwarding is needed and the app stays bound to `127.0.0.1`.

### Option A (recommended): dashboard-managed tunnel

1. Cloudflare dashboard → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel** →
   type **Cloudflared** → name it `dsc-signer`.
2. Choose **Windows**. Cloudflare shows a command containing a long token. Run it in an
   **Administrator PowerShell**:
   ```powershell
   cloudflared.exe service install <TOKEN-FROM-DASHBOARD>
   ```
   This installs cloudflared as an auto-start Windows service.
3. **Public Hostname** tab → add:
   * Subdomain: `sign`, Domain: `yourdomain.com`
   * Service type **HTTP**, URL **`127.0.0.1:8000`** (use `127.0.0.1`, not `localhost`, which
     may resolve to IPv6 `::1`)
4. Open `https://sign.yourdomain.com`.

### Option B: CLI-managed tunnel

```powershell
cloudflared tunnel login
cloudflared tunnel create dsc-signer
cloudflared tunnel route dns dsc-signer sign.yourdomain.com
```

Create `C:\Windows\System32\config\systemprofile\.cloudflared\config.yml` (the folder the
cloudflared **service** reads as LocalSystem) and copy the tunnel credentials JSON from
`%USERPROFILE%\.cloudflared\` into the same folder:

```yaml
tunnel: <TUNNEL-UUID>
credentials-file: C:\Windows\System32\config\systemprofile\.cloudflared\<TUNNEL-UUID>.json
ingress:
  - hostname: sign.yourdomain.com
    service: http://127.0.0.1:8000
  - service: http_status:404
```

```powershell
cloudflared service install
Start-Service cloudflared
```

### How client IPs work

Cloudflare sends the visitor's real IP in `CF-Connecting-IP`. The app trusts that header (and
`X-Forwarded-For` as a fallback) **only** when the request comes from `TRUSTED_PROXIES`
(`127.0.0.1`, i.e. cloudflared on this machine). Keep `HOST=127.0.0.1` so nobody on your LAN can
reach the app directly and spoof the header.

**Optional extra layer:** in Zero Trust → **Access** → **Applications**, protect
`sign.yourdomain.com` with an email one-time-PIN policy. Visitors then need both a Cloudflare
Access login and an app login.

---

## 7. Keep the laptop (and token) awake

A sleeping laptop or a power-saved USB port takes the token offline. From an Administrator
PowerShell, while on AC power:

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /SETACTIVE SCHEME_CURRENT
```

These turn off sleep and hibernate, make closing the lid do nothing, and disable USB selective
suspend. Also uncheck *"Allow the computer to turn off this device to save power"* for the USB
Root Hubs in Device Manager → Power Management.

If the token is unplugged and replugged, the worker reconnects on its next health check
(every 15 s).

---

## 8. Using the app

1. **Upload** one or more PDFs (up to 20 per upload, 25 MB each by default).
2. **Choose a placement mode:**
   * **Visual:** the whole first PDF is shown in a scrolling preview. Scroll (or type a page
     number) to the page you want, drag on it to draw the box, drag the box to move it, and
     drag the corner handle to resize it. Size presets: Small 150×50, Medium 200×70, Large
     250×90 pt (with no box yet, they place one on the page in view). The box is signed on the
     page you drew it on, at the same relative position in every uploaded file. On phones and
     tablets, use a size preset to create the box and drag it into place, since a finger drag
     on the page scrolls.
   * **Page & Position:** first, last, all, or specific pages (`8`, `1,3,8`, `2-5`), a corner or
     bottom-centre preset (or custom X-from-left / Y-from-bottom margins), and width/height in
     points (72 pt = 1 inch; A4 = 595 × 842 pt).
   * **Text Anchor:** finds text such as `Authorized Signatory` and places the signature
     above, below, right of, or over it, for the first, last or every occurrence. Needs a
     text-based PDF (scans have no text). If the text isn't found, the job fails with a clear
     message.
3. Optionally edit **Reason** and **Location**, then click **Queue for signing**, either
   the button in the preview toolbar (next to the PDF) or the one under the form.
4. **My signing queue** refreshes every 3 s (`QUEUED #n → PROCESSING → COMPLETED / FAILED`).
   When a document you just queued finishes, its signed PDF opens in the same preview pane,
   at the signed page, with a green **Signed PDF** bar: check the stamp, then click
   **Download** (`<name>_signed.pdf`) or **Close**. If you've already started placing the next
   upload, it isn't replaced; a message tells you the document is signed instead. **Preview**
   on any completed row shows it again, and **Close** returns to your upload with its box
   intact. Untick **Auto-open signed PDF** to turn the automatic preview off; the browser
   remembers the choice.

The preview scrolls through the whole document, zooms (**−** / **+** / **Fit**), and has a
page box: type a page number and press Enter to jump straight to it in long PDFs.

Regular users see only the documents they queued themselves. Nobody else can list, preview,
download or delete them, except admins. Admins get an **All users** checkbox above the queue
that shows everyone's documents with an **Owner** column, and they can preview, download or
remove any of them. The Admin Panel's audit log records who previewed and downloaded what,
and marks it when an admin opened someone else's document.

The stamp looks like Adobe Acrobat's: the certificate holder's name in large text on the
left, and *"Digitally signed by <name> / Date: yyyy.mm.dd HH:MM:SS +05'30'"* (plus Reason and
Location if given) on the right, with no border. `SIGN_STAMP_STYLE=classic` in `.env` switches to
a boxed text stamp instead. Rotated and cropped pages are handled: the stamp is drawn upright
where you placed it.

**Logo watermark.** The logo in `branding\logo.png` is shown in the stamp
(`SIGN_STAMP_LOGO=auto`, the default). `SIGN_STAMP_LOGO_POSITION` picks where:

| Value | Look |
|---|---|
| `watermark-left` (default) | Faded watermark at the left edge, behind the name; the text layout is unchanged |
| `watermark-center` | Faded watermark centred behind the text |
| `beside` | Full-colour logo in its own space at the left; the text moves right |

`SIGN_STAMP_LOGO_OPACITY` (0.0 invisible to 1.0 solid, default 0.2) sets how faded the
watermark is. To use a different image, replace that file or point `.env` at another one (a
PNG with a transparent background works best; JPEG also works). Set `SIGN_STAMP_LOGO=`
(blank) to turn the logo off.

```ini
SIGN_STAMP_LOGO=auto
SIGN_STAMP_LOGO_POSITION=watermark-left
SIGN_STAMP_LOGO_OPACITY=0.2
```

The logo is scaled to fit the stamp, and large images are downscaled. Restart the service
after changing it. If the file is missing or unreadable, documents are still signed without the
watermark, and `logs\app.log` shows a warning. Use only artwork you have the right to use. Other
companies' logos, such as Adobe's, are their trademarks.

"All pages" and "all occurrences" add one signature per page or occurrence, each a
separate token operation. That's slower, so it is capped by `MAX_SIGNATURES_PER_DOC`.

Uploaded and signed files are deleted after `FILE_RETENTION_MINUTES`.

---

## 9. Admin Panel

`/admin` (admins only; also localhost-only if `ADMIN_LOCALHOST_ONLY=true`):

* **USB token:** live status, token label, certificate holder, issuer, expiry, queue length.
* **Users:** create logins (username, password, full name, admin flag, optional allowed
  IPs/CIDRs, optional device lock). The **Active** toggle disables a user and ends all their
  sessions immediately. You can also edit, reset passwords (which ends their sessions), force a
  logout, or delete a user. You can't disable, demote or delete yourself or the last admin.
* **Device lock (TOFU):** with *Lock to first device* on, the first browser the user logs in
  from is trusted automatically. Any other browser or device is blocked with *"Device not
  authorized. Contact Admin to whitelist this device."* and appears as **Pending** under the
  user and in the audit log, where **Approve device** is one click. Revoking a device ends its
  sessions. Devices are identified by a signed, HttpOnly, 5-year cookie, plus a browser
  fingerprint (user agent, screen, time zone...) that is recorded for review. If someone clears
  their cookies, their browser counts as a new device.
* **Global IP whitelist:** add IPs/CIDRs, use **Whitelist my current IP**, and toggle
  **Enforce whitelist**. When enforced, unlisted IPs get `403 Access Denied (IP Not
  Whitelisted)` before the login page loads. The laptop itself (localhost) is always allowed so
  you can't lock yourself out, and the panel refuses to enforce the whitelist (or remove an
  entry) if that would block your current remote IP.
* **Access audit log:** logins, failures, blocked IPs and devices, admin actions, downloads,
  in IST, with **Approve device** / **Whitelist IP** buttons on blocked entries.

Repeated failed logins (8 in 15 minutes per IP or username) are throttled.

---

## 10. Testing without the token

You can exercise the whole app with a `.p12`/`.pfx` file instead of the token. In `.env`:

```ini
SIGNER_BACKEND=pkcs12
PKCS12_PATH=C:\path\to\test.p12
PKCS12_PASSPHRASE=...
```

Switch back to `SIGNER_BACKEND=pkcs11` for real use. Signatures from a self-signed test
certificate show as "validity unknown" in Acrobat; that is expected.

---

## 11. Troubleshooting

| Badge / error | Fix |
|---|---|
| `NO_DRIVER` | Install the ePass2003 driver, or fix `PKCS11_LIB_PATH` (section 2.1) |
| `NO_TOKEN` | Plug the token in. Check `list_token.py`. Under the service, try `install_service.ps1 -RunAsUser` |
| `Token labelled ... not found` | Copy the label from `list_token.py` into `TOKEN_LABEL`, or leave it blank |
| `PIN_ERROR` | Fix `TOKEN_PIN`, then `Restart-Service DSCSigner`. Don't retry blindly: the token locks |
| `NO_CERT` | Certificate expired, or `CERT_LABEL` doesn't match. Run `list_token.py` |
| `Signing failed: ... Mechanism` | Set `PKCS11_USE_RAW_MECHANISM=true` and restart |
| Login loops back to the login page | Open the site over **https** (Cloudflare) or `http://127.0.0.1`. Secure cookies don't work over plain-http LAN addresses |
| `403 Access Denied (IP Not Whitelisted)` | Whitelist the IP from the laptop itself at `http://127.0.0.1:8000/admin` |
| Preview doesn't render | The browser needs internet access for the PDF.js and Tailwind CDNs |
| Text anchor not found | The PDF is a scan, or the text is split oddly. Use Visual or Page & Position |
| Timestamp errors | Check `TSA_URL`, or leave it empty |

Logs: `logs\app.log` (application) and `logs\service.log` (service stdout/stderr).

---

## 12. Security notes

* Never commit or share `.env` (it is in `.gitignore`). It holds the token PIN and `SECRET_KEY`.
  Changing `SECRET_KEY` logs everyone out and resets all device registrations.
* Sessions are stored server-side in SQLite (`data\dsc_signer.db`), so disabling a user or
  revoking a device takes effect on their next request. Mutating requests need a CSRF token.
* Anyone who can log in can sign documents with your DSC. Give accounts only to people you
  trust, turn on device lock and per-user IP restrictions, and review the audit log.
* Back up `data\dsc_signer.db` and `.env` if you want to keep users and settings across
  reinstalls.

## Project layout

```text
app/
  main.py           FastAPI app: IP whitelist middleware, auth, signing & admin routes
  config.py         pydantic-settings (.env loader)
  database.py       SQLite models: users, whitelisted IPs, devices, audit log, sessions, jobs
  security.py       bcrypt, sessions, Cloudflare IP extraction, IP/CIDR checks, device lock
  placement.py      coordinate math for the Visual, Page/Preset and Text-Anchor modes
  signer_worker.py  single-threaded PKCS#11 session + pyHanko signing worker
  cleanup.py        purges expired PDFs, sessions and old log rows
templates/          login.html, index.html, admin.html
static/app.js       PDF.js preview, box drag/resize, fingerprint, polling, admin actions
scripts/
  install_windows.ps1   venv, dependencies, .env creation
  install_service.ps1   NSSM Windows service
  list_token.py         driver check + certificate listing (no PIN)
uploads/ signed/ data/ logs/   runtime folders (git-ignored contents)
```
