"""
api/analyze.py — Analysis Endpoints (v3).

POST /api/v1/analyze-packet   → ML traffic classification
POST /api/v1/analyze-ioc      → Multi-source IOC lookup
POST /api/v1/ioc/check        → Alias for analyze-ioc (cleaner REST path)
"""
import logging
from fastapi import APIRouter

from schemas.event import PacketAnalysisRequest, IOCAnalysisRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post("/analyze-packet", summary="Classify network packet traffic via ML")
async def analyze_packet(body: PacketAnalysisRequest) -> dict:
    from ml_engine.predictor import predict_packet, TRAINED_FEATURES
    features = {
        "Init Bwd Win Bytes":    body.Init_Bwd_Win_Bytes,
        "Fwd IAT Min":           body.Fwd_IAT_Min,
        "Init Fwd Win Bytes":    body.Init_Fwd_Win_Bytes,
        "Fwd Seg Size Min":      body.Fwd_Seg_Size_Min,
        "Packet Length Min":     body.Packet_Length_Min,
        "Fwd Packet Length Min": body.Fwd_Packet_Length_Min,
        "Bwd IAT Min":           body.Bwd_IAT_Min,
        "PSH Flag Count":        body.PSH_Flag_Count,
        "Bwd Packet Length Min": body.Bwd_Packet_Length_Min,
        "Protocol":              body.Protocol,
    }
    result = predict_packet(features)
    return {"status": "ok", "result": result}


@router.post("/analyze-ioc", summary="Multi-source IOC reputation lookup")
async def analyze_ioc(body: IOCAnalysisRequest) -> dict:
    from services.ioc_service import analyze_ioc as _analyze
    result = _analyze(body.value)
    return {"status": "ok", "result": result}


@router.post("/ioc/check", summary="IOC check (REST alias)")
async def ioc_check(body: IOCAnalysisRequest) -> dict:
    from services.ioc_service import analyze_ioc as _analyze
    result = _analyze(body.value)
    return {"status": "ok", "result": result}
