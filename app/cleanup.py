"""Background task that purges uploaded/signed PDFs older than FILE_RETENTION_MINUTES."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select

from .config import settings
from .database import AuditLog, Job, db_session, utcnow
from .security import purge_expired_sessions
from .signer_worker import STATUS_COMPLETED, STATUS_EXPIRED, STATUS_FAILED

log = logging.getLogger("dsc.cleanup")

AUDIT_RETENTION_DAYS = 180
JOB_ROW_RETENTION_DAYS = 30


def _unlink(path: str) -> None:
    if not path:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as exc:
        log.warning("Could not delete %s: %s", path, exc)


def run_cleanup_once() -> int:
    """Delete expired files and mark their jobs EXPIRED. Returns number of jobs purged."""
    cutoff = utcnow() - timedelta(minutes=settings.FILE_RETENTION_MINUTES)
    purged = 0
    with db_session() as db:
        jobs = db.scalars(
            select(Job).where(
                Job.files_purged.is_(False),
                Job.created_at < cutoff,
                Job.status.in_([STATUS_COMPLETED, STATUS_FAILED, STATUS_EXPIRED]),
            )
        ).all()
        for job in jobs:
            _unlink(job.input_path)
            _unlink(job.output_path)
            job.files_purged = True
            if job.status == STATUS_COMPLETED:
                job.status = STATUS_EXPIRED
            purged += 1
        # forget very old job rows and audit entries
        db.execute(delete(Job).where(Job.created_at < utcnow() - timedelta(days=JOB_ROW_RETENTION_DAYS),
                                     Job.files_purged.is_(True)))
        db.execute(delete(AuditLog).where(AuditLog.ts < utcnow() - timedelta(days=AUDIT_RETENTION_DAYS)))
        db.commit()
        purge_expired_sessions(db)

    # Orphan files (e.g. left after a crash) — anything on disk older than retention
    limit = time.time() - settings.FILE_RETENTION_MINUTES * 60
    for folder in (settings.UPLOAD_DIR, settings.SIGNED_DIR):
        for f in Path(folder).glob("*"):
            if f.name == ".gitkeep" or not f.is_file():
                continue
            try:
                if f.stat().st_mtime < limit:
                    # Do not remove files of jobs still waiting in the queue
                    with db_session() as db:
                        active = db.scalar(
                            select(Job.id).where(Job.input_path == str(f), Job.files_purged.is_(False),
                                                 Job.status.in_(["QUEUED", "PROCESSING"]))
                        )
                    if not active:
                        f.unlink(missing_ok=True)
            except OSError:
                pass
    if purged:
        log.info("Cleanup purged files of %d job(s)", purged)
    return purged


async def cleanup_loop(interval_seconds: int = 60) -> None:
    while True:
        try:
            await asyncio.to_thread(run_cleanup_once)
        except Exception:  # noqa: BLE001
            log.exception("Cleanup run failed")
        await asyncio.sleep(interval_seconds)
