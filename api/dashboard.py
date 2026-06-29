"""
api/dashboard.py — Dashboard / Frontend API (v3).

GET  /api/v1/alerts              → paginated list
GET  /api/v1/alerts/{id}         → single alert detail
GET  /api/v1/alerts/stats        → counts by severity
GET  /api/v1/statistics          → full dashboard statistics
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.alert import Alert
from models.database import get_db
from schemas.event import AlertListResponse, AlertResponse, StatisticsResponse
from services.alert_service import get_alert_by_id, get_alerts, get_statistics

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Dashboard"])


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List enriched alerts (paginated)",
)
async def list_alerts(
    severity:  str | None = Query(default=None, description="Filter: Low|Medium|High|Critical"),
    upload_id: int | None = Query(default=None, description="Filter by upload ID"),
    limit:     int = Query(default=50, ge=1, le=200),
    offset:    int = Query(default=0,  ge=0),
    db: AsyncSession = Depends(get_db),
) -> AlertListResponse:
    total, alerts = await get_alerts(db, severity=severity, limit=limit,
                                     offset=offset, upload_id=upload_id)
    return AlertListResponse(
        total=total,
        alerts=[AlertResponse.model_validate(a) for a in alerts],
    )


@router.get(
    "/alerts/stats",
    summary="Severity statistics",
)
async def alert_stats(db: AsyncSession = Depends(get_db)) -> dict:
    result = await db.execute(
        select(Alert.severity, func.count(Alert.id).label("count"))
        .group_by(Alert.severity)
    )
    rows = result.all()
    stats: dict[str, int] = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for severity, count in rows:
        stats[severity] = count
    total = sum(stats.values())
    return {"total": total, "by_severity": stats}


@router.get(
    "/statistics",
    response_model=StatisticsResponse,
    summary="Full dashboard statistics",
)
async def statistics(db: AsyncSession = Depends(get_db)) -> StatisticsResponse:
    stats = await get_statistics(db)
    return StatisticsResponse(**stats)


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    alert = await get_alert_by_id(alert_id, db)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return AlertResponse.model_validate(alert)
