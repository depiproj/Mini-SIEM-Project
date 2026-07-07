"""
services/retention.py — Data retention / cleanup job.

Purges Alert and LogUpload rows older than RETENTION_DAYS so the database
doesn't grow unbounded on a long-running instance. Runs once at startup and
then once every 24 hours for as long as the app is up.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from models.alert import Alert
from models.database import AsyncSessionLocal
from models.log_upload import LogUpload

logger = logging.getLogger(__name__)

_RUN_INTERVAL_SECONDS = 24 * 60 * 60  # once a day


async def purge_old_data(retention_days: int) -> tuple[int, int]:
    """Delete alerts/uploads older than `retention_days`. Returns (alerts_deleted, uploads_deleted)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with AsyncSessionLocal() as session:
        alert_result = await session.execute(
            delete(Alert).where(Alert.created_at < cutoff)
        )
        upload_result = await session.execute(
            delete(LogUpload).where(LogUpload.created_at < cutoff)
        )
        await session.commit()

        alerts_deleted = alert_result.rowcount or 0
        uploads_deleted = upload_result.rowcount or 0

    if alerts_deleted or uploads_deleted:
        logger.info(
            "Retention purge: removed %d alerts and %d upload records older than %d days.",
            alerts_deleted, uploads_deleted, retention_days,
        )
    return alerts_deleted, uploads_deleted


async def retention_loop(retention_days: int) -> None:
    """Background task: purge on startup, then every 24h. Cancel-safe."""
    while True:
        try:
            await purge_old_data(retention_days)
        except Exception as e:
            logger.error("Retention purge failed: %s", e)
        try:
            await asyncio.sleep(_RUN_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break