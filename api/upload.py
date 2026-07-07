"""
api/upload.py — Log File Upload & Auto-Processing Endpoint.

POST /api/v1/upload-log
  Accepts a log file upload, auto-detects format, parses events,
  runs the detection engine, generates alerts, and returns results.
"""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_api_key
from models.database import get_db
from models.log_upload import LogUpload
from models.alert import Alert
from schemas.event import UploadResponse, IOCSummary
from parsers.log_parser import parse_log_file
from parsers.ioc_extractor import extract_iocs_from_events
from detection.engine import run_detection
from services.enrichment import map_to_mitre
from services.alert_service import _build_alert_from_detection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Upload"], dependencies=[Depends(require_api_key)])

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post(
    "/upload-log",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and auto-process a log file",
    description=(
        "Accepts Syslog, Apache/Nginx, Linux auth.log, Windows Event Log (JSON/text), "
        "or generic text files. Auto-detects format, parses events, runs the detection "
        "engine, generates alerts with MITRE ATT&CK mappings, and extracts IOCs."
    ),
)
async def upload_log(
    file: UploadFile = File(..., description="Log file to analyze"),
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:
    filename = file.filename or "unknown.log"
    logger.info("Upload received: %s (content_type=%s)", filename, file.content_type)

    # Read file content
    try:
        content_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    file_size = len(content_bytes)
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})"
        )
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Dedup check — same bytes already processed successfully → don't
    # re-run detection and mint duplicate alerts for the same log file.
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    existing = await db.execute(
        select(LogUpload).where(
            LogUpload.content_hash == content_hash,
            LogUpload.status == "done",
        )
    )
    existing_upload = existing.scalars().first()
    if existing_upload is not None:
        logger.info(
            "Duplicate upload detected (hash=%s) — returning cached result from upload_id=%d",
            content_hash[:12], existing_upload.id,
        )
        alerts_result = await db.execute(
            select(Alert.id).where(Alert.upload_id == existing_upload.id)
        )
        alert_ids = [row[0] for row in alerts_result.all()]
        return UploadResponse(
            upload_id=existing_upload.id,
            filename=existing_upload.filename,
            log_format=existing_upload.log_format,
            total_events=existing_upload.total_events,
            total_alerts=existing_upload.total_alerts,
            alerts_created=alert_ids,
            iocs_found=IOCSummary(ips=[], domains=[], urls=[], hashes=[]),
            detections_summary=[],
            message=(
                f"This exact file was already processed as upload #{existing_upload.id} "
                f"({existing_upload.total_alerts} alerts). Skipped re-processing to avoid "
                f"duplicate alerts."
            ),
        )

    # Decode — try UTF-8 first, fall back to latin-1
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = content_bytes.decode("latin-1", errors="replace")

    # Create upload record
    upload_record = LogUpload(
        filename=filename,
        log_format="detecting",
        file_size=file_size,
        content_hash=content_hash,
        status="processing",
    )
    db.add(upload_record)
    await db.flush()
    upload_id = upload_record.id
    logger.info("Upload record created: id=%d", upload_id)

    try:
        # ── Parse ──────────────────────────────────────────────────────────────
        log_format, events = parse_log_file(content, filename)
        upload_record.log_format = log_format
        upload_record.total_events = len(events)

        logger.info("Parsed %d events (format=%s)", len(events), log_format)

        # ── Extract IOCs ────────────────────────────────────────────────────────
        iocs = extract_iocs_from_events(events)
        upload_record.iocs_found = (
            len(iocs["ips"]) + len(iocs["domains"]) +
            len(iocs["urls"]) + len(iocs["hashes"])
        )

        # ── Run Detection Engine ───────────────────────────────────────────────
        detections = run_detection(events)
        logger.info("Detection engine produced %d detections", len(detections))

        # ── Behavioral ML scoring (real, per-batch, per-source-IP) ─────────────
        # See ml_engine/behavior_model.py for what this is and its limitations —
        # it is NOT the network-flow Random Forest model; log events have no
        # packet-level features to feed that model honestly.
        from ml_engine.behavior_model import score_ip_behavior
        behavior_scores = score_ip_behavior(events)

        # ── Generate Alerts ────────────────────────────────────────────────────
        created_alert_ids = []
        detections_summary = []

        for detection in detections:
            alert = await _build_alert_from_detection(
                detection, upload_id, db, behavior_scores=behavior_scores
            )
            created_alert_ids.append(alert.id)
            detections_summary.append({
                "rule": detection.rule_name,
                "severity": detection.severity,
                "mitre": detection.mitre_technique_id,
                "ip": detection.source_ip,
                "alert_id": alert.id,
            })

        upload_record.total_alerts = len(created_alert_ids)
        upload_record.status = "done"
        upload_record.completed_at = datetime.now(timezone.utc)

        logger.info(
            "Upload %d processed: %d events, %d alerts, %d IOCs",
            upload_id, len(events), len(created_alert_ids), upload_record.iocs_found
        )

        return UploadResponse(
            upload_id=upload_id,
            filename=filename,
            log_format=log_format,
            total_events=len(events),
            total_alerts=len(created_alert_ids),
            alerts_created=created_alert_ids,
            iocs_found=IOCSummary(**iocs),
            detections_summary=detections_summary,
            message=(
                f"Successfully processed {len(events)} events from '{filename}'. "
                f"Generated {len(created_alert_ids)} alerts and found "
                f"{upload_record.iocs_found} IOCs."
            ),
        )

    except Exception as e:
        logger.exception("Upload processing failed for %s: %s", filename, e)
        upload_record.status = "error"
        upload_record.error_message = str(e)[:500]
        raise HTTPException(
            status_code=500,
            detail=f"Processing failed: {str(e)[:200]}"
        )


@router.get(
    "/upload-history",
    summary="Get log upload history",
)
async def upload_history(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
) -> dict:
    from sqlalchemy import select, desc
    from schemas.event import UploadHistoryItem
    result = await db.execute(
        select(LogUpload).order_by(desc(LogUpload.created_at)).limit(limit)
    )
    uploads = result.scalars().all()
    return {
        "total": len(uploads),
        "uploads": [UploadHistoryItem.model_validate(u) for u in uploads],
    }