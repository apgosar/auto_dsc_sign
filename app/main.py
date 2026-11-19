"""FastAPI application: IP whitelist middleware, auth, signing jobs, admin panel."""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .cleanup import cleanup_loop
from .config import BASE_DIR, settings
from .database import (
    AuditLog,
    Device,
    Job,
    User,
    UserSession,
    WhitelistedIP,
    add_audit,
    db_session,
    get_db,
    init_db,
    set_app_setting,
)
from .placement import PlacementError, compute_boxes
from .security import (
    DEVICE_COOKIE,
    DEVICE_COOKIE_MAX_AGE,
    SESSION_COOKIE,
    AuthContext,
    check_device,
    create_session,
    destroy_session,
    dummy_verify,
    get_client_ip,
    get_device_id,
    global_whitelist_enforced,
    hash_password,
    invalidate_user_sessions,
    ip_globally_allowed,
    ip_in_list,
    is_loopback,
    load_session,
    login_throttle,
    new_device_id,
    parse_network,
    sign_value,
    user_ip_allowed,
    validate_ip_list,
    validate_new_password,
    verify_password,
)
from .signer_worker import STATUS_COMPLETED, STATUS_FAILED, STATUS_QUEUED, worker

# --------------------------------------------------------------------------- logging
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
_handler = logging.handlers.RotatingFileHandler(LOG_DIR / "app.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
logging.getLogger("dsc").addHandler(_handler)
logging.getLogger("dsc").setLevel(logging.INFO)
logging.getLogger("dsc").addHandler(logging.StreamHandler())
log = logging.getLogger("dsc.app")


# --------------------------------------------------------------------------- startup
def bootstrap_admin() -> None:
    with db_session() as db:
        if db.scalar(select(func.count(User.id))) > 0:
            return
        if not settings.INITIAL_ADMIN_PASS:
            raise RuntimeError("No users exist yet: set INITIAL_ADMIN_USER and INITIAL_ADMIN_PASS in .env")
        err = validate_new_password(settings.INITIAL_ADMIN_PASS)
        if err:
            raise RuntimeError(f"INITIAL_ADMIN_PASS: {err}")
        db.add(
            User(
                username=settings.INITIAL_ADMIN_USER.strip().lower(),
                password_hash=hash_password(settings.INITIAL_ADMIN_PASS),
                full_name="Administrator",
                is_admin=True,
                is_active=True,
            )
        )
        add_audit(db, "ADMIN_BOOTSTRAPPED", username=settings.INITIAL_ADMIN_USER, detail="Initial admin created")
        log.warning("Created initial admin user %r. Change its password from the Admin Panel "
                    "and remove INITIAL_ADMIN_PASS from .env.", settings.INITIAL_ADMIN_USER)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.validate_for_startup()
    init_db()
    bootstrap_admin()
    worker.start()
    task = asyncio.create_task(cleanup_loop())
    log.info("DSC signer web app started on %s:%s", settings.HOST, settings.PORT)
    try:
        yield
    finally:
        task.cancel()
        await asyncio.to_thread(worker.stop)


app = FastAPI(title="DSC Signer", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
_TZ = ZoneInfo(settings.SIGN_TIMEZONE)


def _fmt_ist(dt) -> str:
    if not dt:
        return "—"
    return dt.astimezone(_TZ).strftime("%d-%m-%Y %H:%M:%S")


def _ua_short(ua: str) -> str:
    if not ua:
        return "—"
    browser = next((b for b in ("Edg", "OPR", "Firefox", "Chrome", "Safari") if b in ua), "Browser")
    browser = {"Edg": "Edge", "OPR": "Opera"}.get(browser, browser)
    osname = next((o for o, k in (("Windows", "Windows"), ("Android", "Android"), ("iOS", "iPhone"),
                                  ("iPadOS", "iPad"), ("macOS", "Mac OS"), ("Linux", "Linux")) if k in ua), "")
    return f"{browser} on {osname}" if osname else browser


templates.env.filters["ist"] = _fmt_ist
templates.env.filters["ua_short"] = _ua_short


# --------------------------------------------------------------------------- middleware
_ip_block_log: dict[str, float] = {}


@app.middleware("http")
async def ip_whitelist_middleware(request: Request, call_next):
    ip = get_client_ip(request)
    request.state.client_ip = ip

    def _check() -> bool:
        with db_session() as db:
            if not global_whitelist_enforced(db):
                return True
            if ip_globally_allowed(db, ip):
                return True
            now = time.time()
            if now - _ip_block_log.get(ip, 0) > 600:  # log each IP at most every 10 min
                _ip_block_log[ip] = now
                add_audit(db, "IP_BLOCKED", ip=ip, user_agent=request.headers.get("user-agent", ""),
                          detail=f"{request.method} {request.url.path}")
            return False

    if not await asyncio.to_thread(_check):
        return HTMLResponse(
            "<!doctype html><title>403</title><body style='font-family:sans-serif;padding:3rem'>"
            "<h1>403 Access Denied (IP Not Whitelisted)</h1>"
            f"<p>Your IP address <code>{ip}</code> is not on the allow list.</p></body>",
            status_code=403,
        )
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# --------------------------------------------------------------------------- auth deps
def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:512]


def _ip(request: Request) -> str:
    return getattr(request.state, "client_ip", None) or get_client_ip(request)


def optional_auth(request: Request, db: Session = Depends(get_db)) -> Optional[AuthContext]:
    return load_session(db, request)


def _is_api(request: Request) -> bool:
    p = request.url.path
    return p.startswith("/api/") or p.startswith("/admin/api/")


class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _login_required_handler(request: Request, _exc: LoginRequired):
    if _is_api(request):
        return JSONResponse({"detail": "Not logged in"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


def require_user(request: Request, auth: Optional[AuthContext] = Depends(optional_auth)) -> AuthContext:
    if auth is None:
        raise LoginRequired()
    # Per-user IP restriction is enforced on every request, not only at login.
    if not user_ip_allowed(auth.user, _ip(request)):
        raise HTTPException(403, "Your IP address is not allowed for this account.")
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("x-csrf-token", "") != auth.session.csrf_token:
            raise HTTPException(403, "CSRF check failed. Reload the page.")
    return auth


def require_admin(request: Request, auth: AuthContext = Depends(require_user)) -> AuthContext:
    if not auth.user.is_admin:
        raise HTTPException(403, "Admin only")
    if settings.ADMIN_LOCALHOST_ONLY and not is_loopback(_ip(request)):
        raise HTTPException(403, "Admin Panel is only available from the host machine.")
    return auth


def _set_cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, secure=settings.COOKIE_SECURE,
                        samesite="lax", path="/")


# --------------------------------------------------------------------------- pages
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, auth: Optional[AuthContext] = Depends(optional_auth)):
    if auth:
        return RedirectResponse("/", status_code=303)
    resp = templates.TemplateResponse(request, "login.html", {})
    if not get_device_id(request):
        _set_cookie(resp, DEVICE_COOKIE, sign_value(new_device_id()), DEVICE_COOKIE_MAX_AGE)
    return resp


@app.get("/", response_class=HTMLResponse)
def index_page(request: Request, auth: AuthContext = Depends(require_user)):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": auth.user,
            "csrf": auth.session.csrf_token,
            "default_reason": settings.SIGN_REASON,
            "default_location": settings.SIGN_LOCATION,
            "max_mb": settings.MAX_UPLOAD_MB,
            "max_files": settings.MAX_FILES_PER_UPLOAD,
            "retention": settings.FILE_RETENTION_MINUTES,
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username)).all()
    devices = db.scalars(select(Device).order_by(Device.created_at.desc())).all()
    by_user: dict[int, list[Device]] = {}
    for d in devices:
        by_user.setdefault(d.user_id, []).append(d)
    active_sessions = dict(db.execute(select(UserSession.user_id, func.count(UserSession.id)).group_by(UserSession.user_id)).all())
    ips = db.scalars(select(WhitelistedIP).order_by(WhitelistedIP.created_at)).all()
    logs = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(300)).all()
    pending_devices = {d.id: d for d in devices if not d.approved}
    my_ip = _ip(request)
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "user": auth.user,
            "csrf": auth.session.csrf_token,
            "users": users,
            "devices_by_user": by_user,
            "active_sessions": active_sessions,
            "ips": ips,
            "logs": logs,
            "pending_devices": pending_devices,
            "my_ip": my_ip,
            "my_ip_listed": is_loopback(my_ip) or ip_in_list(my_ip, [i.cidr for i in ips]),
            "enforce_ip": global_whitelist_enforced(db),
            "token": worker.get_status(),
        },
    )


# --------------------------------------------------------------------------- auth API
class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    fingerprint: str = Field(default="", max_length=128)


@app.post("/api/login")
def api_login(body: LoginBody, request: Request, db: Session = Depends(get_db)):
    if request.headers.get("x-requested-with") != "fetch":
        raise HTTPException(400, "Bad request")
    ip, ua = _ip(request), _ua(request)
    username = body.username.strip().lower()
    keys = (f"ip:{ip}", f"user:{username}")
    if login_throttle.is_locked(*keys):
        add_audit(db, "LOGIN_THROTTLED", username=username, ip=ip, user_agent=ua)
        raise HTTPException(429, f"Too many failed attempts. Try again in {settings.LOGIN_LOCKOUT_MINUTES} minutes.")

    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        dummy_verify()
    if user is None or not verify_password(body.password, user.password_hash):
        login_throttle.fail(*keys)
        add_audit(db, "LOGIN_FAILED", username=username, ip=ip, user_agent=ua, detail="Bad username or password")
        raise HTTPException(401, "Invalid username or password.")
    if not user.is_active:
        add_audit(db, "LOGIN_BLOCKED_DISABLED", username=username, user_id=user.id, ip=ip, user_agent=ua)
        raise HTTPException(403, "This account is disabled. Contact the administrator.")
    if not user_ip_allowed(user, ip):
        add_audit(db, "LOGIN_BLOCKED_IP", username=username, user_id=user.id, ip=ip, user_agent=ua,
                  detail=f"Allowed: {user.allowed_ip}")
        raise HTTPException(403, "Login not allowed from your IP address. Contact Admin.")

    device_id = get_device_id(request) or new_device_id()
    result = check_device(db, user, device_id=device_id, fingerprint=body.fingerprint, ip=ip, user_agent=ua)
    if not result.allowed:
        resp = JSONResponse({"detail": result.message}, status_code=403)
        _set_cookie(resp, DEVICE_COOKIE, sign_value(device_id), DEVICE_COOKIE_MAX_AGE)
        return resp

    login_throttle.reset(*keys)
    cookie = create_session(db, user, device_id=device_id, ip=ip, user_agent=ua)
    add_audit(db, "LOGIN_SUCCESS", username=username, user_id=user.id, ip=ip, user_agent=ua, device_pk=result.device.id)
    resp = JSONResponse({"ok": True, "redirect": "/"})
    _set_cookie(resp, SESSION_COOKIE, cookie, settings.SESSION_HOURS * 3600)
    _set_cookie(resp, DEVICE_COOKIE, sign_value(device_id), DEVICE_COOKIE_MAX_AGE)
    return resp


@app.post("/api/logout")
def api_logout(request: Request, db: Session = Depends(get_db)):
    destroy_session(db, request)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
def api_me(auth: AuthContext = Depends(require_user)):
    u = auth.user
    return {"username": u.username, "full_name": u.full_name, "is_admin": u.is_admin}


@app.get("/api/token-status")
def api_token_status(_auth: AuthContext = Depends(require_user)):
    return worker.get_status()


@app.get("/healthz")
def healthz():
    return {"ok": True}


# --------------------------------------------------------------------------- jobs API
def _job_dict(job: Job, queue_pos: Optional[int] = None) -> dict:
    return {
        "id": job.id,
        "filename": job.original_filename,
        "mode": job.mode,
        "status": job.status,
        "error": job.error,
        "signature_count": job.signature_count or len(json.loads(job.boxes_json or "[]")),
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "queue_position": queue_pos,
        "download_url": f"/api/jobs/{job.id}/download" if job.status == STATUS_COMPLETED and not job.files_purged else None,
    }


def _safe_name(name: str) -> str:
    name = Path(name or "document.pdf").name
    keep = "".join(c for c in name if c.isalnum() or c in " ._-()") or "document.pdf"
    return keep[:200]


@app.post("/api/jobs")
def api_create_jobs(
    request: Request,
    files: list[UploadFile] = File(...),
    mode: str = Form(...),
    params: str = Form("{}"),
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
):
    if mode not in ("visual", "preset", "anchor"):
        raise HTTPException(400, "Unknown placement mode")
    try:
        p = json.loads(params or "{}")
        if not isinstance(p, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "params must be a JSON object") from None
    if not files:
        raise HTTPException(400, "No files uploaded")
    if len(files) > settings.MAX_FILES_PER_UPLOAD:
        raise HTTPException(400, f"At most {settings.MAX_FILES_PER_UPLOAD} files per upload")

    max_bytes = settings.MAX_UPLOAD_MB * 1024 * 1024
    created: list[dict] = []
    for up in files:
        name = _safe_name(up.filename or "document.pdf")
        data = up.file.read(max_bytes + 1)
        job = Job(id=str(uuid.uuid4()), user_id=auth.user.id, original_filename=name, mode=mode,
                  params_json=json.dumps(p), input_path="")
        if len(data) > max_bytes:
            job.status, job.error = STATUS_FAILED, f"File larger than {settings.MAX_UPLOAD_MB} MB"
        elif not data.lstrip()[:5].startswith(b"%PDF"):
            job.status, job.error = STATUS_FAILED, "Not a PDF file"
        else:
            path = settings.UPLOAD_DIR / f"{job.id}.pdf"
            path.write_bytes(data)
            job.input_path = str(path)
            try:
                boxes = compute_boxes(str(path), mode, p, settings.MAX_SIGNATURES_PER_DOC)
                job.boxes_json = json.dumps([b.to_dict() for b in boxes])
                job.status = STATUS_QUEUED
            except PlacementError as exc:
                job.status, job.error = STATUS_FAILED, str(exc)
        if job.status == STATUS_FAILED:
            job.finished_at = job.created_at
        db.add(job)
        db.commit()
        if job.status == STATUS_QUEUED:
            worker.enqueue(job.id)
        created.append(_job_dict(job))
    add_audit(db, "JOBS_SUBMITTED", username=auth.user.username, user_id=auth.user.id, ip=_ip(request),
              user_agent=_ua(request), detail=f"{len(created)} file(s), mode={mode}")
    return {"jobs": created}


@app.get("/api/jobs")
def api_list_jobs(scope: str = "mine", auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)):
    q = select(Job).order_by(Job.created_at.desc()).limit(100)
    if not (scope == "all" and auth.user.is_admin):
        q = q.where(Job.user_id == auth.user.id)
    jobs = db.scalars(q).all()
    queued = db.scalars(select(Job.id).where(Job.status == STATUS_QUEUED).order_by(Job.created_at)).all()
    pos = {jid: i + 1 for i, jid in enumerate(queued)}
    return {"jobs": [_job_dict(j, pos.get(j.id)) for j in jobs]}


def _own_job(db: Session, auth: AuthContext, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if job is None or (job.user_id != auth.user.id and not auth.user.is_admin):
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/jobs/{job_id}/download")
def api_download(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)):
    job = _own_job(db, auth, job_id)
    if job.status != STATUS_COMPLETED or job.files_purged or not Path(job.output_path).is_file():
        raise HTTPException(404, "Signed file not available (not finished or expired)")
    stem = Path(job.original_filename).stem
    add_audit(db, "JOB_DOWNLOADED", username=auth.user.username, user_id=auth.user.id, ip=_ip(request),
              detail=job.original_filename)
    return FileResponse(job.output_path, media_type="application/pdf", filename=f"{stem}_signed.pdf")


@app.delete("/api/jobs/{job_id}")
def api_delete_job(job_id: str, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)):
    job = _own_job(db, auth, job_id)
    if job.status == "PROCESSING":
        raise HTTPException(409, "Job is being signed right now")
    for pth in (job.input_path, job.output_path):
        if pth:
            Path(pth).unlink(missing_ok=True)
    db.delete(job)  # a QUEUED job deleted here is skipped by the worker
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- admin API
def _audit_admin(db: Session, request: Request, auth: AuthContext, event: str, detail: str, **kw) -> None:
    add_audit(db, event, username=auth.user.username, user_id=auth.user.id, ip=_ip(request),
              user_agent=_ua(request), detail=detail, **kw)


def _get_user(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    return u


def _other_active_admins(db: Session, exclude_id: int) -> int:
    return db.scalar(select(func.count(User.id)).where(User.is_admin.is_(True), User.is_active.is_(True), User.id != exclude_id))


class NewUserBody(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.@\-]+$")
    password: str = Field(max_length=256)
    full_name: str = Field(default="", max_length=128)
    is_admin: bool = False
    allowed_ip: str = Field(default="", max_length=512)
    enforce_device_lock: bool = False


@app.post("/admin/api/users")
def admin_create_user(body: NewUserBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    username = body.username.strip().lower()
    if db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(409, "Username already exists")
    if err := validate_new_password(body.password):
        raise HTTPException(400, err)
    if err := validate_ip_list(body.allowed_ip):
        raise HTTPException(400, err)
    u = User(username=username, password_hash=hash_password(body.password), full_name=body.full_name.strip(),
             is_admin=body.is_admin, allowed_ip=body.allowed_ip.strip(), enforce_device_lock=body.enforce_device_lock)
    db.add(u)
    db.commit()
    _audit_admin(db, request, auth, "USER_CREATED", f"{username} (admin={body.is_admin})")
    return {"ok": True, "id": u.id}


class ActiveBody(BaseModel):
    is_active: bool


@app.post("/admin/api/users/{user_id}/active")
def admin_set_active(user_id: int, body: ActiveBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    u = _get_user(db, user_id)
    if u.id == auth.user.id and not body.is_active:
        raise HTTPException(400, "You cannot disable your own account")
    if u.is_admin and not body.is_active and _other_active_admins(db, u.id) == 0:
        raise HTTPException(400, "Cannot disable the last active admin")
    u.is_active = body.is_active
    if not body.is_active:
        invalidate_user_sessions(db, u.id, commit=False)
    db.commit()
    _audit_admin(db, request, auth, "USER_ENABLED" if body.is_active else "USER_DISABLED", u.username)
    return {"ok": True}


class UpdateUserBody(BaseModel):
    full_name: str = Field(default="", max_length=128)
    is_admin: bool = False
    allowed_ip: str = Field(default="", max_length=512)
    enforce_device_lock: bool = False


@app.post("/admin/api/users/{user_id}/update")
def admin_update_user(user_id: int, body: UpdateUserBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    u = _get_user(db, user_id)
    if err := validate_ip_list(body.allowed_ip):
        raise HTTPException(400, err)
    if u.is_admin and not body.is_admin:
        if u.id == auth.user.id:
            raise HTTPException(400, "You cannot remove your own admin rights")
        if _other_active_admins(db, u.id) == 0:
            raise HTTPException(400, "Cannot demote the last admin")
    u.full_name = body.full_name.strip()
    u.is_admin = body.is_admin
    u.allowed_ip = body.allowed_ip.strip()
    u.enforce_device_lock = body.enforce_device_lock
    db.commit()
    _audit_admin(db, request, auth, "USER_UPDATED",
                 f"{u.username}: admin={u.is_admin} ip={u.allowed_ip or '-'} device_lock={u.enforce_device_lock}")
    return {"ok": True}


class PasswordBody(BaseModel):
    password: str = Field(max_length=256)


@app.post("/admin/api/users/{user_id}/password")
def admin_reset_password(user_id: int, body: PasswordBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    u = _get_user(db, user_id)
    if err := validate_new_password(body.password):
        raise HTTPException(400, err)
    u.password_hash = hash_password(body.password)
    if u.id != auth.user.id:
        invalidate_user_sessions(db, u.id, commit=False)
    db.commit()
    _audit_admin(db, request, auth, "PASSWORD_RESET", u.username)
    return {"ok": True}


@app.post("/admin/api/users/{user_id}/logout")
def admin_force_logout(user_id: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    u = _get_user(db, user_id)
    if u.id == auth.user.id:
        raise HTTPException(400, "Use Logout to end your own session")
    invalidate_user_sessions(db, u.id)
    _audit_admin(db, request, auth, "SESSIONS_REVOKED", u.username)
    return {"ok": True}


@app.delete("/admin/api/users/{user_id}")
def admin_delete_user(user_id: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    u = _get_user(db, user_id)
    if u.id == auth.user.id:
        raise HTTPException(400, "You cannot delete your own account")
    if u.is_admin and _other_active_admins(db, u.id) == 0:
        raise HTTPException(400, "Cannot delete the last admin")
    name = u.username
    for job in db.scalars(select(Job).where(Job.user_id == u.id)).all():
        if job.status == "PROCESSING":
            raise HTTPException(409, "User has a document being signed right now; try again in a moment")
        for pth in (job.input_path, job.output_path):
            if pth:
                Path(pth).unlink(missing_ok=True)
    db.execute(delete(Job).where(Job.user_id == u.id))
    invalidate_user_sessions(db, u.id, commit=False)
    db.delete(u)
    db.commit()
    _audit_admin(db, request, auth, "USER_DELETED", name)
    return {"ok": True}


class IPBody(BaseModel):
    cidr: str = Field(max_length=64)
    note: str = Field(default="", max_length=255)


def _add_ip(db: Session, cidr: str, note: str, by: str) -> str:
    try:
        net = str(parse_network(cidr))
    except ValueError:
        raise HTTPException(400, f"Invalid IP/CIDR: {cidr}") from None
    if net.endswith("/32") or net.endswith("/128"):
        net = net.rsplit("/", 1)[0]
    if db.scalar(select(WhitelistedIP.id).where(WhitelistedIP.cidr == net)):
        raise HTTPException(409, f"{net} is already whitelisted")
    db.add(WhitelistedIP(cidr=net, note=note.strip(), created_by=by))
    db.commit()
    return net


@app.post("/admin/api/ips")
def admin_add_ip(body: IPBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    net = _add_ip(db, body.cidr, body.note, auth.user.username)
    _audit_admin(db, request, auth, "IP_WHITELISTED", net)
    return {"ok": True, "cidr": net}


@app.post("/admin/api/ips/mine")
def admin_add_my_ip(request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    ip = _ip(request)
    net = _add_ip(db, ip, f"Added via 'Whitelist My Current IP' by {auth.user.username}", auth.user.username)
    _audit_admin(db, request, auth, "IP_WHITELISTED", net)
    return {"ok": True, "cidr": net}


@app.delete("/admin/api/ips/{ip_id}")
def admin_delete_ip(ip_id: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(WhitelistedIP, ip_id)
    if not row:
        raise HTTPException(404, "Not found")
    my_ip = _ip(request)
    if global_whitelist_enforced(db) and not is_loopback(my_ip):
        remaining = [r.cidr for r in db.scalars(select(WhitelistedIP).where(WhitelistedIP.id != ip_id))]
        if not ip_in_list(my_ip, remaining):
            raise HTTPException(400, "Removing this entry would lock you out (your IP is only allowed by it).")
    cidr = row.cidr
    db.delete(row)
    db.commit()
    _audit_admin(db, request, auth, "IP_REMOVED", cidr)
    return {"ok": True}


class ToggleBody(BaseModel):
    enabled: bool


@app.post("/admin/api/settings/ip-whitelist")
def admin_toggle_ip_whitelist(body: ToggleBody, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    my_ip = _ip(request)
    if body.enabled and not is_loopback(my_ip):
        if not ip_in_list(my_ip, [r.cidr for r in db.scalars(select(WhitelistedIP))]):
            raise HTTPException(400, f"Your current IP {my_ip} is not whitelisted. Add it first, or you will be locked out.")
    set_app_setting(db, "enforce_global_ip_whitelist", "true" if body.enabled else "false")
    _audit_admin(db, request, auth, "IP_WHITELIST_ENFORCED" if body.enabled else "IP_WHITELIST_DISABLED", "")
    return {"ok": True}


def _get_device(db: Session, device_pk: int) -> Device:
    d = db.get(Device, device_pk)
    if not d:
        raise HTTPException(404, "Device not found")
    return d


@app.post("/admin/api/devices/{device_pk}/approve")
def admin_approve_device(device_pk: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    d = _get_device(db, device_pk)
    d.approved = True
    db.commit()
    _audit_admin(db, request, auth, "DEVICE_APPROVED", f"{d.user.username}: {d.user_agent[:80]}", device_pk=d.id)
    return {"ok": True}


@app.post("/admin/api/devices/{device_pk}/revoke")
def admin_revoke_device(device_pk: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    d = _get_device(db, device_pk)
    d.approved = False
    db.execute(delete(UserSession).where(UserSession.user_id == d.user_id, UserSession.device_id == d.device_id))
    db.commit()
    _audit_admin(db, request, auth, "DEVICE_REVOKED", f"{d.user.username}: {d.user_agent[:80]}", device_pk=d.id)
    return {"ok": True}


@app.delete("/admin/api/devices/{device_pk}")
def admin_delete_device(device_pk: int, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    d = _get_device(db, device_pk)
    name = d.user.username
    db.execute(delete(UserSession).where(UserSession.user_id == d.user_id, UserSession.device_id == d.device_id))
    db.delete(d)
    db.commit()
    _audit_admin(db, request, auth, "DEVICE_DELETED", name)
    return {"ok": True}
