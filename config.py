"""
config.py — Central configuration loaded from environment variables.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./siem.db")

# ── Email / SMTP ──────────────────────────────────────────────────────────────
SMTP_HOST: str     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str     = os.getenv("SMTP_USER", "your-email@gmail.com")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "your-app-password")
ALERT_RECIPIENTS: list[str] = os.getenv(
    "ALERT_RECIPIENTS", "soc-team@company.com"
).split(",")

# ── VirusTotal (IOC Enrichment) ───────────────────────────────────────────────
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
IOC_LOOKUP_ENABLED: bool = bool(VIRUSTOTAL_API_KEY)

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# ── AlienVault OTX ───────────────────────────────────────────────────────────
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

# ── ML Engine ─────────────────────────────────────────────────────────────────
ML_MODEL_PATH: str = os.getenv(
    "ML_MODEL_PATH",
    str(BASE_DIR / "ml_engine" / "security_rf_model.pkl")
)
ML_ENABLED: bool = os.getenv("ML_ENABLED", "true").lower() == "true"

# ── Auth ──────────────────────────────────────────────────────────────────────
# Shared-secret API key required via the 'X-API-Key' header. Leave blank to
# disable auth for local development (a warning is logged when this happens).
API_KEY: str = os.getenv("API_KEY", "")

# ── CORS ──────────────────────────────────────────────────────────────────────
# Comma-separated list of allowed origins, e.g. "https://dashboard.example.com".
# Defaults to localhost-only so the API isn't wide open by default.
_default_cors = "http://localhost:8000,http://127.0.0.1:8000"
CORS_ORIGINS: list[str] = [
    o.strip() for o in os.getenv("CORS_ORIGINS", _default_cors).split(",") if o.strip()
]

# ── Data Retention ────────────────────────────────────────────────────────────
# Alerts and upload records older than this many days are purged by the
# retention job. Set to 0 to disable automatic purging.
RETENTION_DAYS: int = int(os.getenv("RETENTION_DAYS", "90"))

# ── App ───────────────────────────────────────────────────────────────────────
API_TITLE: str    = "Mini-SIEM Alerting System"
API_VERSION: str  = "3.1.0"
DEBUG: bool       = os.getenv("DEBUG", "true").lower() == "true"