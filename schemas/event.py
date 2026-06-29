"""
schemas/event.py — Pydantic v2 schemas (v3 - full SIEM).
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


class EventPayload(BaseModel):
    event_type:  str = Field(..., min_length=1, max_length=120, example="brute_force_login")
    severity:    str = Field(..., example="High")
    source_ip:   str = Field(..., example="192.168.1.105")
    timestamp:   str = Field(..., example="2024-07-15T14:23:01Z")
    description: str = Field(..., min_length=1, example="Multiple failed SSH login attempts.")

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        normalised = v.strip().capitalize()
        if normalised not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{v}'")
        return normalised


class IOCResult(BaseModel):
    malicious:    Optional[bool] = None
    reputation:   Optional[str]  = None
    provider:     Optional[str]  = None
    raw_response: Optional[str]  = None


class MitreMapping(BaseModel):
    technique_id:   Optional[str] = None
    technique_name: Optional[str] = None
    tactic:         Optional[str] = None


class MLResult(BaseModel):
    prediction:   Optional[str]  = None
    is_malicious: Optional[bool] = None
    ml_enabled:   Optional[bool] = None


class EnrichedAlert(BaseModel):
    event_type:  str
    severity:    str
    source_ip:   str
    timestamp:   str
    description: str
    mitre: MitreMapping
    ioc:   IOCResult
    ml:    Optional[MLResult] = None


class AlertResponse(BaseModel):
    id:                   int
    event_type:           str
    severity:             str
    source_ip:            str
    timestamp:            str
    description:          str
    mitre_technique_id:   Optional[str]
    mitre_technique_name: Optional[str]
    mitre_tactic:         Optional[str]
    ioc_malicious:        Optional[bool]
    ioc_reputation:       Optional[str]
    ioc_provider:         Optional[str]
    ml_prediction:        Optional[str]
    ml_is_malicious:      Optional[bool]
    rule_name:            Optional[str]
    username:             Optional[str]
    upload_id:            Optional[int]
    notified:             bool
    created_at:           datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    total:  int
    alerts: list[AlertResponse]


class IngestionAck(BaseModel):
    status:   str
    alert_id: int
    message:  str


class PacketAnalysisRequest(BaseModel):
    Init_Bwd_Win_Bytes:    float = Field(default=0, example=65535)
    Fwd_IAT_Min:           float = Field(default=0, example=100.0)
    Init_Fwd_Win_Bytes:    float = Field(default=0, example=65535)
    Fwd_Seg_Size_Min:      float = Field(default=0, example=20.0)
    Packet_Length_Min:     float = Field(default=0, example=40.0)
    Fwd_Packet_Length_Min: float = Field(default=0, example=40.0)
    Bwd_IAT_Min:           float = Field(default=0, example=200.0)
    PSH_Flag_Count:        float = Field(default=0, example=1.0)
    Bwd_Packet_Length_Min: float = Field(default=0, example=40.0)
    Protocol:              float = Field(default=6, example=6.0)


class IOCAnalysisRequest(BaseModel):
    value: str = Field(..., example="185.220.101.34")


# ── Upload response schemas ───────────────────────────────────────────────────

class IOCSummary(BaseModel):
    ips:     list[str]
    domains: list[str]
    urls:    list[str]
    hashes:  list[dict]


class UploadResponse(BaseModel):
    upload_id:       int
    filename:        str
    log_format:      str
    total_events:    int
    total_alerts:    int
    alerts_created:  list[int]
    iocs_found:      IOCSummary
    detections_summary: list[dict]
    message:         str


class UploadHistoryItem(BaseModel):
    id:           int
    filename:     str
    log_format:   str
    file_size:    Optional[int]
    total_events: int
    total_alerts: int
    iocs_found:   int
    status:       str
    created_at:   datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class StatisticsResponse(BaseModel):
    total_alerts:       int
    by_severity:        dict
    by_mitre_tactic:    dict
    by_event_type:      dict
    top_source_ips:     list[dict]
    ioc_stats:          dict
    upload_count:       int
    recent_activity:    list[dict]
