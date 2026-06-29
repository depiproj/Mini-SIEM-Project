"""
models/alert.py — ORM model for enriched security alerts (v3 - full SIEM).
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from models.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # ── Raw Event Fields ──────────────────────────────────────────────────────
    event_type:  Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    severity:    Mapped[str] = mapped_column(String(20),  nullable=False, index=True)
    source_ip:   Mapped[str] = mapped_column(String(45),  nullable=False, index=True)
    timestamp:   Mapped[str] = mapped_column(String(50),  nullable=False)
    description: Mapped[str] = mapped_column(Text,        nullable=False)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre_technique_id:   Mapped[str | None] = mapped_column(String(30),  nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    mitre_tactic:         Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ── IOC Reputation ────────────────────────────────────────────────────────
    ioc_malicious:    Mapped[bool | None] = mapped_column(Boolean,     nullable=True)
    ioc_reputation:   Mapped[str | None]  = mapped_column(String(100), nullable=True)
    ioc_provider:     Mapped[str | None]  = mapped_column(String(50),  nullable=True)
    ioc_raw_response: Mapped[str | None]  = mapped_column(Text,        nullable=True)

    # ── ML Engine ─────────────────────────────────────────────────────────────
    ml_prediction:   Mapped[str | None]  = mapped_column(String(100), nullable=True)
    ml_is_malicious: Mapped[bool | None] = mapped_column(Boolean,     nullable=True)

    # ── Source tracking ───────────────────────────────────────────────────────
    upload_id:   Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    rule_name:   Mapped[str | None] = mapped_column(String(100), nullable=True)
    username:    Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ── Pipeline Metadata ─────────────────────────────────────────────────────
    notified:   Mapped[bool]     = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} severity={self.severity!r} "
            f"event_type={self.event_type!r} source_ip={self.source_ip!r}>"
        )
