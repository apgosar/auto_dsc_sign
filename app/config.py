"""Application settings loaded from the project-root `.env` file (pydantic-settings)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Hardware token (PKCS#11) ----
    PKCS11_LIB_PATH: str = r"C:\Windows\System32\eps2003csp11.dll"
    # Token label as reported by the driver. Leave blank to use the first token present.
    TOKEN_LABEL: str = "ePass2003"
    # User PIN of the USB token. Lives ONLY in .env on the host.
    TOKEN_PIN: str = ""
    # Optional substring matched against the certificate's PKCS#11 label or subject CN.
    CERT_LABEL: str = ""
    # Use raw RSA mechanism (hash computed in Python) if the token rejects CKM_SHA256_RSA_PKCS.
    PKCS11_USE_RAW_MECHANISM: bool = False

    # Signer backend: "pkcs11" (USB token, production) or "pkcs12" (a .p12/.pfx file, for testing only).
    SIGNER_BACKEND: str = "pkcs11"
    PKCS12_PATH: str = ""
    PKCS12_PASSPHRASE: str = ""

    # ---- Signature appearance ----
    TSA_URL: str = ""
    SIGN_REASON: str = ""
    SIGN_LOCATION: str = ""
    SIGN_TIMEZONE: str = "Asia/Kolkata"
    # "acrobat": two-column stamp like Adobe Acrobat (name left, details right, no border)
    # "classic": single text block with a border
    SIGN_STAMP_STYLE: str = "acrobat"
    # Optional watermark image (PNG with transparency works best) drawn faded behind the
    # stamp text. Only used with SIGN_STAMP_STYLE=acrobat. Blank = no watermark.
    SIGN_STAMP_LOGO: str = ""
    SIGN_STAMP_LOGO_OPACITY: float = Field(default=0.15, ge=0.0, le=1.0)
    MAX_SIGNATURES_PER_DOC: int = 50

    # ---- Auth / security ----
    SECRET_KEY: str = ""
    INITIAL_ADMIN_USER: str = "admin"
    INITIAL_ADMIN_PASS: str = ""
    SESSION_HOURS: int = 12
    # Mark cookies Secure. Browsers accept Secure cookies on http://localhost, and the
    # public URL is HTTPS via Cloudflare, so leave this on unless you test over plain LAN http.
    COOKIE_SECURE: bool = True
    # Initial value; can then be toggled from the Admin Panel (stored in DB).
    ENFORCE_GLOBAL_IP_WHITELIST: bool = False
    # Peers whose CF-Connecting-IP / X-Forwarded-For headers are trusted (cloudflared runs locally).
    TRUSTED_PROXIES: str = "127.0.0.1,::1"
    # If true, /admin is only reachable from the host itself (in addition to is_admin).
    ADMIN_LOCALHOST_ONLY: bool = False
    LOGIN_MAX_FAILURES: int = 8
    LOGIN_LOCKOUT_MINUTES: int = 15

    # ---- Files ----
    FILE_RETENTION_MINUTES: int = 60
    MAX_UPLOAD_MB: int = 25
    MAX_FILES_PER_UPLOAD: int = 20
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    SIGNED_DIR: Path = BASE_DIR / "signed"
    DATABASE_PATH: Path = BASE_DIR / "data" / "dsc_signer.db"

    # ---- Server ----
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    TOKEN_HEALTHCHECK_SECONDS: int = Field(default=15, ge=5)

    @field_validator("SIGNER_BACKEND")
    @classmethod
    def _backend(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"pkcs11", "pkcs12"}:
            raise ValueError("SIGNER_BACKEND must be 'pkcs11' or 'pkcs12'")
        return v

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()]

    def validate_for_startup(self) -> None:
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise RuntimeError(
                "SECRET_KEY is missing or too short in .env. Generate one with:\n"
                '  python -c "import secrets; print(secrets.token_hex(32))"'
            )
        for d in (self.UPLOAD_DIR, self.SIGNED_DIR, self.DATABASE_PATH.parent):
            Path(d).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
