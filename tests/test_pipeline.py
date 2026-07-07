"""
tests/test_pipeline.py — Unit + integration tests for the alert pipeline.

Run with:
    pip install pytest pytest-asyncio httpx
    pytest tests/ -v
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# ── Force isolated test environment ───────────────────────────────────────────
# NOTE: we use direct assignment (not setdefault) because a real .env file
# (e.g. one with production DATABASE_URL / API keys) is loaded by config.py
# on import and WILL already be present in os.environ by the time this file
# runs. setdefault() would then silently do nothing, and tests would quietly
# run against the real database / real external APIs instead of an isolated
# in-memory one. That previously caused intermittent "database is locked"
# failures whenever a real server process was also running against siem.db.
import os
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["VIRUSTOTAL_API_KEY"] = ""    # force simulation layer
os.environ["ABUSEIPDB_API_KEY"] = ""
os.environ["OTX_API_KEY"] = ""

from main import app
from models.database import init_db, engine, Base


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_db():
    """Create tables once for the test module."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ─────────────────────────────────────────────────────────────────────────────
# Classification tests
# ─────────────────────────────────────────────────────────────────────────────

class TestClassification:
    def test_valid_severity_passthrough(self):
        from schemas.event import EventPayload
        from services.classification import classify_event

        event = EventPayload(
            event_type="port_scan", severity="Medium",
            source_ip="10.0.0.1", timestamp="2024-01-01T00:00:00Z",
            description="port scan detected",
        )
        result = classify_event(event)
        assert result.severity == "Medium"
        assert not result.escalated

    def test_escalation_brute_force(self):
        from schemas.event import EventPayload
        from services.classification import classify_event

        event = EventPayload(
            event_type="brute_force_login", severity="Low",
            source_ip="1.2.3.4", timestamp="2024-01-01T00:00:00Z",
            description="brute force attempt",
        )
        result = classify_event(event)
        assert result.severity == "High"
        assert result.escalated

    def test_escalation_ransomware_to_critical(self):
        from schemas.event import EventPayload
        from services.classification import classify_event

        event = EventPayload(
            event_type="ransomware_detected", severity="High",
            source_ip="5.5.5.5", timestamp="2024-01-01T00:00:00Z",
            description="ransomware",
        )
        result = classify_event(event)
        assert result.severity == "Critical"
        assert result.escalated

    def test_invalid_severity_rejected(self):
        from pydantic import ValidationError
        from schemas.event import EventPayload

        with pytest.raises(ValidationError):
            EventPayload(
                event_type="test", severity="SUPER_CRITICAL",
                source_ip="1.1.1.1", timestamp="2024-01-01T00:00:00Z",
                description="bad severity",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichment:
    def test_mitre_brute_force(self):
        from services.enrichment import map_to_mitre

        mapping = map_to_mitre("brute_force_login")
        assert mapping.technique_id == "T1110"
        assert "Brute Force" in mapping.technique_name

    def test_mitre_ransomware(self):
        from services.enrichment import map_to_mitre

        mapping = map_to_mitre("ransomware_detected")
        assert mapping.technique_id == "T1486"

    def test_mitre_unknown(self):
        from services.enrichment import map_to_mitre

        mapping = map_to_mitre("totally_unknown_event_xyz")
        assert mapping.technique_id is None

    @pytest.mark.asyncio
    async def test_ioc_simulated_malicious(self):
        from services.enrichment import lookup_ioc

        result = await lookup_ioc("185.220.101.34")   # seeded as malicious
        assert result.malicious is True
        assert result.reputation == "malicious"

    @pytest.mark.asyncio
    async def test_ioc_simulated_clean(self):
        from services.enrichment import lookup_ioc

        result = await lookup_ioc("8.8.8.8")
        assert result.malicious is False
        assert result.reputation == "clean"


# ─────────────────────────────────────────────────────────────────────────────
# API integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIngestionAPI:
    @pytest.mark.asyncio
    async def test_ingest_valid_event(self, client):
        payload = {
            "event_type": "brute_force_login",
            "severity":   "Low",
            "source_ip":  "10.0.0.1",
            "timestamp":  "2024-07-15T10:00:00Z",
            "description": "Multiple failed SSH logins",
        }
        resp = await client.post("/api/v1/events", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        assert isinstance(data["alert_id"], int)

    @pytest.mark.asyncio
    async def test_ingest_invalid_severity(self, client):
        payload = {
            "event_type": "test", "severity": "EXTREME",
            "source_ip": "1.1.1.1", "timestamp": "2024-01-01T00:00:00Z",
            "description": "test",
        }
        resp = await client.post("/api/v1/events", json=payload)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_ingest_missing_field(self, client):
        resp = await client.post("/api/v1/events", json={"event_type": "test"})
        assert resp.status_code == 422


class TestDashboardAPI:
    @pytest.mark.asyncio
    async def test_list_alerts(self, client):
        resp = await client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "alerts" in data

    @pytest.mark.asyncio
    async def test_alert_stats(self, client):
        resp = await client.get("/api/v1/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_severity" in data
        assert set(data["by_severity"].keys()) == {"Low", "Medium", "High", "Critical"}

    @pytest.mark.asyncio
    async def test_get_nonexistent_alert(self, client):
        resp = await client.get("/api/v1/alerts/99999")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, client):
        resp = await client.get("/api/v1/alerts?severity=High")
        assert resp.status_code == 200
        data = resp.json()
        for alert in data["alerts"]:
            assert alert["severity"] == "High"

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
