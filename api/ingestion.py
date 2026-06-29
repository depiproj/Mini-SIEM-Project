"""
api/ingestion.py — Event Ingestion Endpoint.

POST /api/v1/events
  Receives a raw security event, runs it through the full alert pipeline,
  and returns an acknowledgement with the created alert ID.

This router is the sole external entry-point for detection engines,
log shippers (Filebeat, Logstash), or any other data source.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import get_db
from schemas.event import EventPayload, IngestionAck
from services.alert_service import process_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Ingestion"])


@router.post(
    "/events",
    response_model=IngestionAck,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security event",
    description=(
        "Accepts a raw security event JSON object, validates it, runs it through "
        "the classification → enrichment → database → notification pipeline, and "
        "returns the created alert's ID."
    ),
)
async def ingest_event(
    payload: EventPayload,
    db: AsyncSession = Depends(get_db),
) -> IngestionAck:
    """
    Full pipeline in one request:
      1. Pydantic validates & normalises the payload.
      2. alert_service.process_event() runs Classification → Enrichment → DB → Notify.
      3. Returns 201 with the alert ID and final severity.
    """
    logger.info(
        "Received event: event_type=%r severity=%r source_ip=%r",
        payload.event_type, payload.severity, payload.source_ip,
    )

    try:
        alert = await process_event(payload, db)
    except Exception as exc:
        logger.exception("Pipeline failure for event_type=%r: %s", payload.event_type, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal pipeline error — see server logs.",
        ) from exc

    return IngestionAck(
        status   = "created",
        alert_id = alert.id,
        message  = (
            f"Alert {alert.id} created with severity '{alert.severity}'. "
            + ("Email notification sent." if alert.notified else "No email (below threshold or disabled).")
        ),
    )
