"""Password hashing, server-side sessions, Cloudflare-aware client IP, IP whitelist and device lock."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.context import CryptContext
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import settings
from .database import (
    Device,
    User,
    UserSession,
    WhitelistedIP,
    add_audit,
    get_app_setting,
    utcnow,
)

SESSION_COOKIE = "dsc_session"
DEVICE_COOKIE = "dsc_device"
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 5  # 5 years

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_serializer = URLSafeSerializer(settings.SECRET_KEY or "unset", salt="dsc-signer-cookies")


# --------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


# Constant-time-ish dummy verify to blunt username enumeration via timing
_DUMMY_HASH = pwd_context.hash(secrets.token_hex(16))


def dummy_verify() -> None:
    pwd_context.verify("x", _DUMMY_HASH)


def validate_new_password(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password.encode("utf-8")) > 72:
        return "Password must be at most 72 bytes (bcrypt limit)."
    return None


# --------------------------------------------------------------------------- client IP
def _is_trusted_proxy(host: str) -> bool:
    return host in settings.trusted_proxy_list


def get_client_ip(request: Request) -> str:
    """Real client IP. Proxy headers are only honoured when the TCP peer is a trusted proxy
    (cloudflared on localhost); otherwise anyone could spoof CF-Connecting-IP."""
    peer = request.client.host if request.client else ""
    if peer and _is_trusted_proxy(peer):
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return _normalize_ip(cf)
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return _normalize_ip(first)
    return _normalize_ip(peer)


def _normalize_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return ip


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def parse_network(value: str) -> ipaddress._BaseNetwork:
    """Parse '203.0.113.45' or '192.168.1.0/24' into a network. Raises ValueError."""
    return ipaddress.ip_network(value.strip(), strict=False)


def ip_in_list(ip: str, entries: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if addr in parse_network(entry):
                return True
        except ValueError:
            continue
    return False


def global_whitelist_enforced(db: Session) -> bool:
    default = "true" if settings.ENFORCE_GLOBAL_IP_WHITELIST else "false"
    return get_app_setting(db, "enforce_global_ip_whitelist", default) == "true"


def ip_globally_allowed(db: Session, ip: str) -> bool:
    if is_loopback(ip):
        return True  # the host itself can always reach the app (lock-out recovery)
    entries = list(db.scalars(select(WhitelistedIP.cidr)))
    return ip_in_list(ip, entries)


def user_ip_allowed(user: User, ip: str) -> bool:
    if not user.allowed_ip.strip():
        return True
    if is_loopback(ip):
        return True
    return ip_in_list(ip, user.allowed_ip.split(","))


def validate_ip_list(value: str) -> Optional[str]:
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parse_network(part)
        except ValueError:
            return f"Invalid IP/CIDR: {part}"
    return None


# --------------------------------------------------------------------------- signed cookies
def sign_value(value: str) -> str:
    return _serializer.dumps(value)


def unsign_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(_serializer.loads(value))
    except BadSignature:
        return None


def get_device_id(request: Request) -> Optional[str]:
    return unsign_value(request.cookies.get(DEVICE_COOKIE))


def new_device_id() -> str:
    return secrets.token_hex(16)


# --------------------------------------------------------------------------- sessions
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, *, device_id: str, ip: str, user_agent: str) -> str:
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_hash_token(token),
            user_id=user.id,
            device_id=device_id,
            ip=ip,
            user_agent=user_agent[:512],
            csrf_token=secrets.token_urlsafe(24),
            expires_at=utcnow() + timedelta(hours=settings.SESSION_HOURS),
        )
    )
    user.last_login_at = utcnow()
    db.commit()
    return sign_value(token)


@dataclass
class AuthContext:
    user: User
    session: UserSession


def load_session(db: Session, request: Request) -> Optional[AuthContext]:
    token = unsign_value(request.cookies.get(SESSION_COOKIE))
    if not token:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == _hash_token(token)))
    if not sess:
        return None
    now = utcnow()
    if sess.expires_at <= now:
        db.delete(sess)
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        db.execute(delete(UserSession).where(UserSession.user_id == sess.user_id))
        db.commit()
        return None
    # A device revoked by the admin kills the session too (when device lock is enforced).
    if user.enforce_device_lock and not _device_is_approved(db, user.id, sess.device_id):
        db.delete(sess)
        db.commit()
        return None
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    return AuthContext(user=user, session=sess)


def destroy_session(db: Session, request: Request) -> None:
    token = unsign_value(request.cookies.get(SESSION_COOKIE))
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == _hash_token(token)))
        db.commit()


def invalidate_user_sessions(db: Session, user_id: int, commit: bool = True) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    if commit:
        db.commit()


def purge_expired_sessions(db: Session) -> int:
    res = db.execute(delete(UserSession).where(UserSession.expires_at <= utcnow()))
    db.commit()
    return res.rowcount or 0


# --------------------------------------------------------------------------- device lock
def _device_is_approved(db: Session, user_id: int, device_id: str) -> bool:
    if not device_id:
        return False
    return (
        db.scalar(
            select(Device.id).where(
                Device.user_id == user_id, Device.device_id == device_id, Device.approved.is_(True)
            )
        )
        is not None
    )


@dataclass
class DeviceCheck:
    allowed: bool
    device: Device
    message: str = ""


def check_device(
    db: Session, user: User, *, device_id: str, fingerprint: str, ip: str, user_agent: str
) -> DeviceCheck:
    """Register/look up the device and decide whether this login is allowed.

    * Device lock off  -> always allowed; device recorded and auto-approved for visibility.
    * Device lock on   -> TOFU: if the user has no approved device, this one becomes approved.
                          Otherwise an unknown device is stored as *pending* and the login blocked.
    """
    now = utcnow()
    dev = db.scalar(select(Device).where(Device.user_id == user.id, Device.device_id == device_id))
    if dev is None:
        dev = Device(
            user_id=user.id,
            device_id=device_id,
            fingerprint=fingerprint[:64],
            user_agent=user_agent[:512],
            first_ip=ip,
            last_ip=ip,
            approved=False,
        )
        db.add(dev)
        db.flush()

    if dev.fingerprint and fingerprint and dev.fingerprint != fingerprint:
        add_audit(
            db,
            "DEVICE_FINGERPRINT_CHANGED",
            username=user.username,
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
            device_pk=dev.id,
            detail=f"old={dev.fingerprint[:12]} new={fingerprint[:12]}",
            commit=False,
        )
        dev.fingerprint = fingerprint[:64]

    dev.last_ip = ip
    dev.user_agent = user_agent[:512]
    dev.last_seen_at = now

    if not user.enforce_device_lock:
        dev.approved = True
        db.commit()
        return DeviceCheck(True, dev)

    if dev.approved:
        db.commit()
        return DeviceCheck(True, dev)

    has_approved = (
        db.scalar(select(Device.id).where(Device.user_id == user.id, Device.approved.is_(True))) is not None
    )
    if not has_approved:
        dev.approved = True
        add_audit(
            db,
            "DEVICE_TOFU_REGISTERED",
            username=user.username,
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
            device_pk=dev.id,
            detail="First device trusted on first use",
            commit=False,
        )
        db.commit()
        return DeviceCheck(True, dev)

    add_audit(
        db,
        "LOGIN_BLOCKED_DEVICE",
        username=user.username,
        user_id=user.id,
        ip=ip,
        user_agent=user_agent,
        device_pk=dev.id,
        detail="Unapproved device; pending admin approval",
        commit=False,
    )
    db.commit()
    return DeviceCheck(False, dev, "Device not authorized. Contact Admin to whitelist this device.")


# --------------------------------------------------------------------------- login throttling
class LoginThrottle:
    """In-memory failed-login counter per (ip) and per (username)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    def _window(self) -> float:
        return settings.LOGIN_LOCKOUT_MINUTES * 60

    def is_locked(self, *keys: str) -> bool:
        now = time.time()
        with self._lock:
            for k in keys:
                hits = [t for t in self._fails.get(k, []) if now - t < self._window()]
                self._fails[k] = hits
                if len(hits) >= settings.LOGIN_MAX_FAILURES:
                    return True
        return False

    def fail(self, *keys: str) -> None:
        now = time.time()
        with self._lock:
            for k in keys:
                self._fails.setdefault(k, []).append(now)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)


login_throttle = LoginThrottle()
