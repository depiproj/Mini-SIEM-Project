"""
services/alert_service.py — Alert Pipeline Orchestrator (v3 - full SIEM).

Pipeline stages:
  1. Classification   (severity + escalation)
  2. Enrichment       (MITRE + multi-source IOC)
  3. ML Prediction    (Random Forest network traffic classifier)
  4. Persist to DB
  5. Notification     (email for High/Critical)
"""
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text

from models.alert import Alert
from schemas.event import EventPayload
from services.classification import classify_event
from services.enrichment import enrich_event
from services.notification import notify

logger = logging.getLogger(__name__)


async def process_event(event: EventPayload, db: AsyncSession) -> Alert:
    # ── Stage 1: Classification ───────────────────────────────────────────────
    classification = classify_event(event)
    if classification.escalated:
        logger.warning("Severity escalated for %r: %s", event.event_type, classification.note)

    # ── Stage 2: Enrichment (MITRE + IOC) ────────────────────────────────────
    enriched = await enrich_event(event, classification.severity)

    # ── Stage 3: ML Prediction ────────────────────────────────────────────────
    # Only runs if the caller supplied genuine network-flow features. Log
    # events (the vast majority of alerts here) have no such data, so
    # ml_prediction stays None for them rather than being fed a fabricated
    # feature vector that would always yield the same meaningless verdict.
    ml_prediction   = None
    ml_is_malicious = None
    if event.network_features:
        try:
            from ml_engine.predictor import predict_packet
            ml_result = predict_packet(event.network_features)
            if ml_result and ml_result.get("ml_enabled"):
                ml_prediction   = ml_result.get("prediction")
                ml_is_malicious = ml_result.get("is_malicious")
        except Exception as e:
            logger.warning("ML stage skipped: %s", e)

    # ── Stage 4: Persist ──────────────────────────────────────────────────────
    alert = Alert(
        event_type  = enriched.event_type,
        severity    = enriched.severity,
        source_ip   = enriched.source_ip,
        timestamp   = enriched.timestamp,
        description = enriched.description,

        mitre_technique_id   = enriched.mitre.technique_id,
        mitre_technique_name = enriched.mitre.technique_name,
        mitre_tactic         = enriched.mitre.tactic,

        ioc_malicious    = enriched.ioc.malicious,
        ioc_reputation   = enriched.ioc.reputation,
        ioc_provider     = enriched.ioc.provider,
        ioc_raw_response = enriched.ioc.raw_response,

        ml_prediction   = ml_prediction,
        ml_is_malicious = ml_is_malicious,

        notified  = False,
        upload_id = None,
    )
    db.add(alert)
    await db.flush()
    logger.info("Alert id=%s persisted — severity=%s", alert.id, alert.severity)

    # ── Stage 5: Notification ─────────────────────────────────────────────────
    notified = await notify(alert)
    if notified:
        alert.notified = True

    return alert


async def _build_alert_from_detection(
    detection,
    upload_id: int,
    db: AsyncSession,
    behavior_scores: dict | None = None,
) -> Alert:
    """
    Create an Alert ORM object from a DetectionResult (from detection engine).
    Runs IOC enrichment on the source IP.
    """
    from services.enrichment import map_to_mitre, lookup_ioc

    # IOC enrichment
    ioc = await lookup_ioc(detection.source_ip)

    # ML prediction: log-parsed detections (brute force, sudo abuse, etc.) have
    # no network-flow telemetry, so we never feed them into the packet-level
    # Random Forest model (ml_engine/predictor.py) — that would mean making up
    # numbers, which is what caused every alert to previously show "Benign".
    #
    # Instead, `behavior_scores` (computed once per upload batch by
    # ml_engine/behavior_model.score_ip_behavior) holds a genuine, data-backed
    # anomaly verdict per source IP, built from real counts in this file:
    # failed logins, distinct accounts targeted, distinct destinations, event
    # rate. If that's unavailable for some reason, ml_prediction stays None
    # rather than falling back to a fabricated value.
    ml_prediction   = None
    ml_is_malicious = None
    if behavior_scores:
        ip_score = behavior_scores.get(detection.source_ip)
        if ip_score:
            ml_prediction   = f"{ip_score['prediction']} ({ip_score['method']})"
            ml_is_malicious = ip_score["is_malicious"]

    alert = Alert(
        event_type  = detection.event_type,
        severity    = detection.severity,
        source_ip   = detection.source_ip,
        timestamp   = detection.timestamp,
        description = detection.description,

        mitre_technique_id   = detection.mitre_technique_id,
        mitre_technique_name = detection.mitre_technique_name,
        mitre_tactic         = detection.mitre_tactic,

        ioc_malicious    = ioc.malicious,
        ioc_reputation   = ioc.reputation,
        ioc_provider     = ioc.provider,
        ioc_raw_response = ioc.raw_response,

        ml_prediction   = ml_prediction,
        ml_is_malicious = ml_is_malicious,

        notified  = False,
        upload_id = upload_id,
        rule_name = detection.rule_name,
        username  = detection.username,
    )
    db.add(alert)
    await db.flush()

    # Notify for High/Critical
    try:
        notified = await notify(alert)
        if notified:
            alert.notified = True
    except Exception:
        pass

    return alert


async def get_alerts(
    db: AsyncSession,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    upload_id: Optional[int] = None,
) -> tuple[int, list[Alert]]:
    base_q  = select(Alert)
    count_q = select(func.count()).select_from(Alert)

    if severity:
        base_q  = base_q.where(Alert.severity == severity)
        count_q = count_q.where(Alert.severity == severity)

    if upload_id is not None:
        base_q  = base_q.where(Alert.upload_id == upload_id)
        count_q = count_q.where(Alert.upload_id == upload_id)

    base_q = base_q.order_by(desc(Alert.created_at)).limit(limit).offset(offset)

    total_result = await db.execute(count_q)
    total: int   = total_result.scalar_one()

    result = await db.execute(base_q)
    alerts = list(result.scalars().all())
    return total, alerts


async def get_alert_by_id(alert_id: int, db: AsyncSession) -> Optional[Alert]:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one_or_none()


async def get_statistics(db: AsyncSession) -> dict:
    """Aggregate statistics for the dashboard."""
    from sqlalchemy import case
    from models.log_upload import LogUpload

    # Total alerts
    total_result = await db.execute(select(func.count()).select_from(Alert))
    total = total_result.scalar_one()

    # By severity
    sev_result = await db.execute(
        select(Alert.severity, func.count(Alert.id).label("count"))
        .group_by(Alert.severity)
    )
    by_severity = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for sev, cnt in sev_result.all():
        by_severity[sev] = cnt

    # By MITRE tactic
    tactic_result = await db.execute(
        select(Alert.mitre_tactic, func.count(Alert.id).label("count"))
        .where(Alert.mitre_tactic != None)
        .group_by(Alert.mitre_tactic)
        .order_by(desc("count"))
        .limit(10)
    )
    by_tactic = {row[0]: row[1] for row in tactic_result.all() if row[0]}

    # By event type
    type_result = await db.execute(
        select(Alert.event_type, func.count(Alert.id).label("count"))
        .group_by(Alert.event_type)
        .order_by(desc("count"))
        .limit(10)
    )
    by_event_type = {row[0]: row[1] for row in type_result.all()}

    # Top source IPs
    ip_result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"))
        .group_by(Alert.source_ip)
        .order_by(desc("count"))
        .limit(10)
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in ip_result.all()]

    # IOC stats
    ioc_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.ioc_malicious == True)
    )
    malicious_ioc_count = ioc_result.scalar_one()

    # Upload count
    upload_result = await db.execute(select(func.count()).select_from(LogUpload))
    upload_count = upload_result.scalar_one()

    # Recent alerts (last 10)
    recent_result = await db.execute(
        select(Alert)
        .order_by(desc(Alert.created_at))
        .limit(10)
    )
    recent = recent_result.scalars().all()
    recent_activity = [
        {
            "id": a.id,
            "event_type": a.event_type,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "mitre_tactic": a.mitre_tactic,
            "created_at": a.created_at.isoformat() if a.created_at else "",
        }
        for a in recent
    ]

    return {
        "total_alerts": total,
        "by_severity": by_severity,
        "by_mitre_tactic": by_tactic,
        "by_event_type": by_event_type,
        "top_source_ips": top_ips,
        "ioc_stats": {
            "malicious_count": malicious_ioc_count,
            "clean_count": total - malicious_ioc_count,
        },
        "upload_count": upload_count,
        "recent_activity": recent_activity,
    }