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

# ── App ───────────────────────────────────────────────────────────────────────
API_TITLE: str    = "Mini-SIEM Alerting System"
API_VERSION: str  = "3.0.0"
DEBUG: bool       = os.getenv("DEBUG", "true").lower() == "true"
