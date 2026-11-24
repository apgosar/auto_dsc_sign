"""Single-threaded signing worker.

The ePass 2003 PKCS#11 driver (eps2003csp11.dll) is NOT thread safe. Every PKCS#11 call in
this process -- opening the session, logging in, listing certificates, health checks and
signing -- happens on ONE dedicated thread, fed by a ``queue.Queue``. Nothing else in the app
touches the token. Run uvicorn with a single worker process for the same reason.
"""
from __future__ import annotations

import io
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

from sqlalchemy import select

from .config import settings
from .database import Job, db_session, utcnow

log = logging.getLogger("dsc.signer")

STATUS_QUEUED = "QUEUED"
STATUS_PROCESSING = "PROCESSING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_EXPIRED = "EXPIRED"


class FatalTokenError(RuntimeError):
    """An error that must not be retried automatically (e.g. wrong PIN -> token lock risk)."""


class RetryableTokenError(RuntimeError):
    """Token/session problem worth one reconnect + retry."""


# =========================================================================== token status
@dataclass
class TokenStatus:
    connected: bool = False
    state: str = "STARTING"  # STARTING | READY | NO_DRIVER | NO_TOKEN | PIN_ERROR | NO_CERT | ERROR
    message: str = "Worker starting..."
    backend: str = settings.SIGNER_BACKEND
    token_label: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_valid_to: str = ""
    last_check: str = ""
    current_job: Optional[str] = None
    jobs_signed: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


# =========================================================================== backends
def _cert_summary(cert) -> tuple[str, str, str]:
    subj = cert.subject.native
    iss = cert.issuer.native
    cn = subj.get("common_name") or cert.subject.human_friendly
    issuer_cn = iss.get("common_name") or cert.issuer.human_friendly
    valid_to = cert["tbs_certificate"]["validity"]["not_after"].native
    return str(cn), str(issuer_cn), valid_to.strftime("%Y-%m-%d")


class Pkcs12Backend:
    """Test-only backend that signs with a .p12/.pfx file instead of the USB token."""

    name = "pkcs12"

    def __init__(self) -> None:
        self._signer = None

    def ensure_ready(self, status: TokenStatus):
        if self._signer is None:
            from pyhanko.sign import signers

            if not settings.PKCS12_PATH or not Path(settings.PKCS12_PATH).is_file():
                raise FatalTokenError(f"PKCS12_PATH not found: {settings.PKCS12_PATH!r}")
            pw = settings.PKCS12_PASSPHRASE.encode() if settings.PKCS12_PASSPHRASE else None
            signer = signers.SimpleSigner.load_pkcs12(settings.PKCS12_PATH, passphrase=pw)
            if signer is None:
                raise FatalTokenError("Could not load PKCS#12 file (wrong passphrase?)")
            self._signer = signer
            cn, iss, vt = _cert_summary(signer.signing_cert)
            status.token_label = f"PKCS#12 file ({Path(settings.PKCS12_PATH).name})"
            status.cert_subject, status.cert_issuer, status.cert_valid_to = cn, iss, vt
        return self._signer

    def healthcheck(self, status: TokenStatus) -> None:
        self.ensure_ready(status)

    def reset(self) -> None:
        self._signer = None


class Pkcs11Backend:
    """ePass 2003 (or any PKCS#11) USB token. Only ever used from the worker thread."""

    name = "pkcs11"

    def __init__(self) -> None:
        self._lib = None
        self._token = None
        self._session = None
        self._signer = None
        self._pin_blocked = False  # never retry a wrong PIN automatically

    # ---- low level --------------------------------------------------------
    def _load_lib(self):
        if self._lib is None:
            path = settings.PKCS11_LIB_PATH
            if not Path(path).is_file():
                raise RetryableTokenError(
                    f"PKCS#11 driver not found at {path}. Install the ePass 2003 driver (see README)."
                )
            import pkcs11

            self._lib = pkcs11.lib(path)
        return self._lib

    def reset(self) -> None:
        """Drop the session and re-initialise the library (recovers from unplug/replug)."""
        self._signer = None
        if self._session is not None:
            try:
                self._session.close()
            except Exception:  # noqa: BLE001
                pass
        self._session = None
        self._token = None
        if self._lib is not None and hasattr(self._lib, "reinitialize"):
            try:
                self._lib.reinitialize()
            except Exception:  # noqa: BLE001
                self._lib = None

    def _find_token(self):
        import pkcs11

        lib = self._load_lib()
        slots = lib.get_slots(token_present=True)
        tokens = []
        for slot in slots:
            try:
                tokens.append(slot.get_token())
            except pkcs11.exceptions.PKCS11Error:
                continue
        if not tokens:
            raise RetryableTokenError("No USB token detected. Plug in the ePass 2003 token.")
        want = settings.TOKEN_LABEL.strip()
        if want:
            for t in tokens:
                if t.label.strip() == want:
                    return t
            labels = ", ".join(repr(t.label.strip()) for t in tokens)
            raise RetryableTokenError(f"Token labelled {want!r} not found. Present: {labels}. Fix TOKEN_LABEL in .env.")
        return tokens[0]

    def _select_certificate(self, session):
        """Pick the signing certificate: has a matching private key, signing key usage,
        currently valid, optionally filtered by CERT_LABEL (label or subject CN substring)."""
        from asn1crypto import x509
        from pkcs11 import Attribute, ObjectClass

        key_ids: set[bytes] = set()
        key_labels: set[str] = set()
        for k in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
            try:
                key_ids.add(bytes(k[Attribute.ID]))
            except Exception:  # noqa: BLE001
                pass
            try:
                key_labels.add(k[Attribute.LABEL])
            except Exception:  # noqa: BLE001
                pass

        now = datetime.now().astimezone()
        flt = settings.CERT_LABEL.strip().lower()
        candidates = []
        for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
            try:
                der = bytes(obj[Attribute.VALUE])
                cert = x509.Certificate.load(der)
                label = obj[Attribute.LABEL] if obj[Attribute.LABEL] else ""
                cid = bytes(obj[Attribute.ID]) if obj[Attribute.ID] else b""
            except Exception:  # noqa: BLE001
                continue
            has_key = (cid and cid in key_ids) or (label and label in key_labels)
            if not has_key:
                continue  # CA certificates etc.
            ku = cert.key_usage_value.native if cert.key_usage_value else set()
            if ku and not ({"digital_signature", "non_repudiation"} & set(ku)):
                continue  # encryption-only certificate
            cn = str(cert.subject.native.get("common_name", ""))
            if flt and flt not in label.lower() and flt not in cn.lower() and flt not in cert.subject.human_friendly.lower():
                continue
            validity = cert["tbs_certificate"]["validity"]
            nb, na = validity["not_before"].native, validity["not_after"].native
            valid_now = nb <= now <= na
            score = (valid_now, "non_repudiation" in ku, na)
            candidates.append((score, cert, label, cid))
        if not candidates:
            hint = f" matching CERT_LABEL={settings.CERT_LABEL!r}" if flt else ""
            raise FatalTokenError(f"No signing certificate with a private key{hint} found on the token.")
        candidates.sort(key=lambda c: c[0], reverse=True)
        score, cert, label, cid = candidates[0]
        if not score[0]:
            raise FatalTokenError("The signing certificate on the token is expired or not yet valid.")
        return cert, label, cid

    def ensure_ready(self, status: TokenStatus):
        if self._signer is not None:
            return self._signer
        if self._pin_blocked:
            raise FatalTokenError(
                "Token PIN was rejected earlier. Fix TOKEN_PIN in .env and restart the service. "
                "(Automatic retries are disabled to avoid locking the token.)"
            )
        if not settings.TOKEN_PIN:
            raise FatalTokenError("TOKEN_PIN is not set in .env.")
        import pkcs11
        from pyhanko.sign.pkcs11 import PKCS11Signer

        token = self._find_token()
        try:
            session = token.open(user_pin=settings.TOKEN_PIN)
        except (pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinLenRange, pkcs11.exceptions.PinInvalid) as exc:
            self._pin_blocked = True
            raise FatalTokenError(f"Token rejected the PIN ({type(exc).__name__}). Fix TOKEN_PIN and restart.") from exc
        except pkcs11.exceptions.PinLocked as exc:
            self._pin_blocked = True
            raise FatalTokenError("Token PIN is LOCKED. Unlock it with the ePass 2003 utility (SO PIN).") from exc
        except pkcs11.exceptions.UserAlreadyLoggedIn:
            session = token.open()

        try:
            cert, label, cid = self._select_certificate(session)
            kwargs: dict[str, Any] = dict(
                signing_cert=cert,
                use_raw_mechanism=settings.PKCS11_USE_RAW_MECHANISM,
            )
            if cid:
                kwargs["key_id"] = cid
            else:
                kwargs["key_label"] = label
            signer = PKCS11Signer(session, **kwargs)
        except Exception:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
            raise

        self._token, self._session, self._signer = token, session, signer
        cn, iss, vt = _cert_summary(cert)
        status.token_label = token.label.strip()
        status.cert_subject, status.cert_issuer, status.cert_valid_to = cn, iss, vt
        log.info("PKCS#11 session opened: token=%r cert=%r", status.token_label, cn)
        return signer

    def healthcheck(self, status: TokenStatus) -> None:
        if self._signer is None:
            self.ensure_ready(status)
            return
        # Cheap liveness probe: is our token still present?
        lib = self._load_lib()
        present = [s for s in lib.get_slots(token_present=True)]
        if not present:
            self.reset()
            raise RetryableTokenError("USB token was removed.")
        # touch the session so a dead handle is noticed
        try:
            from pkcs11 import Attribute, ObjectClass

            next(iter(self._session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})), None)
        except Exception as exc:  # noqa: BLE001
            self.reset()
            raise RetryableTokenError(f"Token session lost ({type(exc).__name__}); reconnecting.") from exc


# =========================================================================== signing
# pyHanko draws the stamp in unrotated page space, so on a page with /Rotate the text ends up
# sideways. We wrap its appearance step: lay the stamp out at the *displayed* size and give the
# appearance XObject a counter-rotation /Matrix. The viewer maps the rotated BBox onto the
# widget /Rect, so the stamp reads upright. Only ever used on the single worker thread.
_appearance_ctx = threading.local()
_ROTATION_MATRICES = {90: (0, 1, -1, 0, 0, 0), 180: (-1, 0, 0, -1, 0, 0), 270: (0, -1, 1, 0, 0, 0)}


def _install_rotation_patch() -> None:
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.layout import BoxConstraints
    from pyhanko.sign.signers import cms_embedder

    from . import stamp as acrobat_stamp

    cls = cms_embedder.SigAppearanceSetup
    if getattr(cls, "_dsc_rotation_patched", False):
        return
    original_apply = cls.apply

    def apply(self, sig_annot, writer):
        rotation = getattr(_appearance_ctx, "rotation", 0)
        style = getattr(_appearance_ctx, "style", "classic")
        w, h = cms_embedder.annot_width_height(sig_annot)
        if not (w and h):
            return original_apply(self, sig_annot, writer)
        if rotation not in _ROTATION_MATRICES and style != "acrobat":
            return original_apply(self, sig_annot, writer)
        if rotation in (90, 270):
            w, h = h, w

        if style == "acrobat":
            xobj = acrobat_stamp.make_xobject(
                w, h,
                name=self.name or "Signer",
                timestamp=self.timestamp,
                tz_name=settings.SIGN_TIMEZONE,
                reason=getattr(_appearance_ctx, "reason", ""),
                location=getattr(_appearance_ctx, "location", ""),
            )
            sig_annot["/AP"] = generic.DictionaryObject({generic.pdf_name("/N"): writer.add_object(xobj)})
            if "/AS" in sig_annot:
                del sig_annot["/AS"]
            ap_stream = xobj
        else:
            stamp = self._appearance_stamp(writer, BoxConstraints(width=w, height=h))
            if not stamp:
                return None
            stamp.apply_appearance(sig_annot)
            ap_stream = sig_annot["/AP"]["/N"]
            ap_stream = ap_stream.get_object() if hasattr(ap_stream, "get_object") else ap_stream

        if rotation in _ROTATION_MATRICES:
            ap_stream["/Matrix"] = generic.ArrayObject(generic.FloatObject(v) for v in _ROTATION_MATRICES[rotation])
        writer.update_container(sig_annot)
        return None

    cls.apply = apply
    cls._dsc_rotation_patched = True


def _build_stamp_style(reason: str, location: str):
    from pyhanko.pdf_utils.text import TextBoxStyle
    from pyhanko.stamp import TextStampStyle

    lines = ["Digitally signed by", "%(signer)s", "Date: %(ist_ts)s"]
    if reason:
        lines.append("Reason: %(reason)s")
    if location:
        lines.append("Location: %(location)s")
    return TextStampStyle(
        stamp_text="\n".join(lines),
        border_width=1,
        text_box_style=TextBoxStyle(font_size=9),
    )


def _ist_now() -> str:
    tz = ZoneInfo(settings.SIGN_TIMEZONE)
    now = datetime.now(tz)
    label = "IST" if settings.SIGN_TIMEZONE == "Asia/Kolkata" else now.strftime("%Z")
    return now.strftime(f"%d-%m-%Y %H:%M:%S {label}")


def sign_pdf_bytes(signer, data: bytes, boxes: list[dict], *, reason: str, location: str, job_id: str) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers, timestamps

    timestamper = timestamps.HTTPTimeStamper(settings.TSA_URL) if settings.TSA_URL.strip() else None
    style = _build_stamp_style(reason, location)
    current = data
    for n, b in enumerate(boxes, start=1):
        writer = IncrementalPdfFileWriter(io.BytesIO(current), strict=False)
        existing = {f[0] for f in fields.enumerate_sig_fields(writer)} if hasattr(fields, "enumerate_sig_fields") else set()
        field_name = f"DSC_{job_id[:8]}_{n}"
        while field_name in existing:
            field_name += "_x"
        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason or None,
            location=location or None,
            md_algorithm="sha256",
            subfilter=fields.SigSeedSubFilter.PADES,
        )
        spec = fields.SigFieldSpec(
            sig_field_name=field_name,
            on_page=int(b["page_index"]),
            box=(b["x1"], b["y1"], b["x2"], b["y2"]),
        )
        pdf_signer = signers.PdfSigner(meta, signer=signer, timestamper=timestamper, stamp_style=style, new_field_spec=spec)
        out = io.BytesIO()
        _install_rotation_patch()
        _appearance_ctx.rotation = int(b.get("rotation", 0)) % 360
        _appearance_ctx.style = settings.SIGN_STAMP_STYLE
        _appearance_ctx.reason, _appearance_ctx.location = reason, location
        try:
            pdf_signer.sign_pdf(
                writer,
                output=out,
                appearance_text_params={"ist_ts": _ist_now(), "reason": reason, "location": location},
            )
        finally:
            _appearance_ctx.rotation = 0
            _appearance_ctx.style = "classic"
        current = out.getvalue()
    return current


# =========================================================================== worker
class SignerWorker:
    def __init__(self) -> None:
        self.queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self.status = TokenStatus()
        self._status_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.backend = Pkcs12Backend() if settings.SIGNER_BACKEND == "pkcs12" else Pkcs11Backend()

    # ---- public API (any thread) -----------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._requeue_pending()
        self._thread = threading.Thread(target=self._run, name="pkcs11-signer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.queue.put(None)
        if self._thread:
            self._thread.join(timeout=10)

    def enqueue(self, job_id: str) -> None:
        self.queue.put(job_id)

    def get_status(self) -> dict:
        with self._status_lock:
            d = self.status.__dict__.copy()
        d["queue_length"] = self.queue.qsize()
        return d

    # ---- internals (worker thread only) ----------------------------------
    def _set(self, **kw) -> None:
        with self._status_lock:
            for k, v in kw.items():
                setattr(self.status, k, v)
            self.status.last_check = utcnow().isoformat()

    def _requeue_pending(self) -> None:
        with db_session() as db:
            jobs = db.scalars(
                select(Job).where(Job.status.in_([STATUS_QUEUED, STATUS_PROCESSING])).order_by(Job.created_at)
            ).all()
            for j in jobs:
                j.status = STATUS_QUEUED
                self.queue.put(j.id)
            db.commit()
        if jobs:
            log.info("Re-queued %d unfinished job(s) from previous run", len(jobs))

    def _healthcheck(self) -> None:
        try:
            self.backend.healthcheck(self.status)
            self._set(connected=True, state="READY", message="Token ready")
        except FatalTokenError as exc:
            msg = str(exc)
            state = "PIN_ERROR" if "PIN" in msg else ("NO_CERT" if "certificate" in msg else "ERROR")
            self._set(connected=False, state=state, message=msg)
        except RetryableTokenError as exc:
            msg = str(exc)
            state = "NO_DRIVER" if "driver" in msg.lower() else "NO_TOKEN"
            self._set(connected=False, state=state, message=msg)
        except Exception as exc:  # noqa: BLE001
            log.exception("Token health check failed")
            self.backend.reset()
            self._set(connected=False, state="ERROR", message=f"{type(exc).__name__}: {exc}")

    def _run(self) -> None:
        log.info("Signer worker started (backend=%s)", self.backend.name)
        self._healthcheck()
        while not self._stop.is_set():
            try:
                job_id = self.queue.get(timeout=settings.TOKEN_HEALTHCHECK_SECONDS)
            except queue.Empty:
                self._healthcheck()
                continue
            if job_id is None:
                break
            try:
                self._process(job_id)
            except Exception:  # noqa: BLE001
                log.exception("Unexpected error processing job %s", job_id)
            finally:
                self.queue.task_done()
        self.backend.reset()
        log.info("Signer worker stopped")

    def _fail(self, job_id: str, message: str) -> None:
        with db_session() as db:
            job = db.get(Job, job_id)
            if job:
                job.status = STATUS_FAILED
                job.error = message
                job.finished_at = utcnow()
                db.commit()

    def _process(self, job_id: str) -> None:
        with db_session() as db:
            job = db.get(Job, job_id)
            if job is None or job.status != STATUS_QUEUED:
                return
            job.status = STATUS_PROCESSING
            job.started_at = utcnow()
            db.commit()
            input_path, boxes = job.input_path, json.loads(job.boxes_json or "[]")
            params = json.loads(job.params_json or "{}")
            output_path = str(settings.SIGNED_DIR / f"{job.id}.pdf")

        self._set(current_job=job_id)
        try:
            if not Path(input_path).is_file():
                self._fail(job_id, "Uploaded file no longer exists (expired?).")
                return
            data = Path(input_path).read_bytes()
            reason = (params.get("reason") or settings.SIGN_REASON or "").strip()[:200]
            location = (params.get("location") or settings.SIGN_LOCATION or "").strip()[:200]

            signed: Optional[bytes] = None
            last_error = ""
            for attempt in (1, 2):
                try:
                    signer = self.backend.ensure_ready(self.status)
                    self._set(connected=True, state="READY", message="Signing...")
                    signed = sign_pdf_bytes(signer, data, boxes, reason=reason, location=location, job_id=job_id)
                    break
                except FatalTokenError as exc:
                    last_error = str(exc)
                    self._healthcheck_after_error(exc)
                    break
                except Exception as exc:  # noqa: BLE001  (pkcs11 / IO errors -> reconnect once)
                    last_error = f"{type(exc).__name__}: {exc}"
                    log.warning("Signing attempt %d for job %s failed: %s", attempt, job_id, last_error)
                    if not _is_token_error(exc):
                        break  # a PDF problem; retrying with a fresh session won't help
                    self.backend.reset()
                    time.sleep(1.5)
            if signed is None:
                self._fail(job_id, f"Signing failed: {last_error}")
                self._healthcheck()
                return

            tmp = output_path + ".part"
            Path(tmp).write_bytes(signed)
            os.replace(tmp, output_path)
            with db_session() as db:
                job = db.get(Job, job_id)
                if job:
                    job.status = STATUS_COMPLETED
                    job.output_path = output_path
                    job.signature_count = len(boxes)
                    job.finished_at = utcnow()
                    job.error = ""
                    db.commit()
            with self._status_lock:
                self.status.jobs_signed += 1
            self._set(message="Token ready")
            log.info("Job %s signed (%d signature(s))", job_id, len(boxes))
        finally:
            self._set(current_job=None)

    def _healthcheck_after_error(self, exc: Exception) -> None:
        msg = str(exc)
        self._set(connected=False, state="PIN_ERROR" if "PIN" in msg else "ERROR", message=msg)


def _is_token_error(exc: BaseException) -> bool:
    """True if the exception (or anything in its cause chain) came from the token/driver."""
    try:
        import pkcs11

        token_types: tuple = (pkcs11.exceptions.PKCS11Error, RetryableTokenError, OSError)
    except ImportError:
        token_types = (RetryableTokenError, OSError)
    seen = 0
    cur: Optional[BaseException] = exc
    while cur is not None and seen < 10:
        if isinstance(cur, token_types):
            return True
        cur = cur.__cause__ or cur.__context__
        seen += 1
    return False


worker = SignerWorker()
