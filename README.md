# Mini-SIEM v3 — Automated Security Information & Event Management

A production-quality automated SIEM with log ingestion, detection engine, MITRE ATT&CK mapping, IOC enrichment, and ML-based anomaly detection.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env

# Start the server
python main.py
# OR
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Open dashboard
open http://localhost:8000
```

## Architecture

```
Upload Log File
     │
     ▼
Log Parser (auto-detects format)
├── Syslog (RFC 3164 / RFC 5424)
├── Apache / Nginx access & error logs
├── Linux auth.log / secure
├── Windows Event Log (JSON or text)
└── Generic text logs
     │
     ▼
IOC Extractor
├── IPv4 addresses
├── Domains & URLs
└── MD5 / SHA1 / SHA256 hashes
     │
     ▼
Detection Engine (MITRE ATT&CK)
├── Brute Force Detection     → T1110
├── Password Spray            → T1110.003
├── Port Scan                 → T1046
├── PowerShell Abuse          → T1059.001
├── Suspicious Auth           → T1078
├── Privilege Escalation      → T1548.003
├── Repeated Auth Failure     → T1110.001
├── Statistical Anomaly       → ML-based
└── ML Random Forest          → Multi-class
     │
     ▼
Alert Generation (auto)
├── MITRE ATT&CK mapping
├── IOC enrichment (VT / AbuseIPDB / OTX or offline sim)
├── ML prediction
└── DB persistence
     │
     ▼
Dashboard (real-time)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | System health check |
| POST | /api/v1/upload-log | **Upload log file (auto-process)** |
| GET | /api/v1/upload-history | Upload history |
| POST | /api/v1/events | Manual event ingest |
| GET | /api/v1/alerts | Paginated alert list |
| GET | /api/v1/alerts/{id} | Single alert detail |
| GET | /api/v1/alerts/stats | Severity counts |
| GET | /api/v1/statistics | Full dashboard statistics |
| POST | /api/v1/analyze-ioc | IOC reputation lookup |
| POST | /api/v1/ioc/check | IOC check (REST alias) |
| POST | /api/v1/analyze-packet | ML packet classification |

Interactive API docs: http://localhost:8000/docs

## Supported Log Formats

- **Syslog** — RFC 3164 and RFC 5424
- **Apache Combined Log** — access and error logs
- **Nginx** — access and error logs  
- **Linux auth.log** — SSH, sudo, su, PAM
- **Windows Event Log** — JSON export or text format (Event IDs: 4624, 4625, 4688, etc.)
- **Generic text** — best-effort parsing with IP and keyword extraction

## Detection Rules

All detections auto-generate alerts with MITRE ATT&CK mappings:

| Rule | MITRE ID | Trigger |
|------|----------|---------|
| Brute Force Login | T1110 | ≥5 failed logins from same IP |
| Password Spray | T1110.003 | Same IP targeting ≥3 accounts |
| Port Scan | T1046 | Port scan events or many destinations |
| PowerShell Abuse | T1059.001 | Encoded commands, IEX, bypass flags |
| Account Compromise | T1078 | Success after many failures |
| Impossible Login | T1078 | Same user from ≥4 different IPs |
| Sudo/Root Escalation | T1548.003 | Frequent sudo or root commands |
| Statistical Anomaly | T1046 | IP activity > 2.5σ from mean |
| ML Detection | T1046 | Random Forest flags malicious patterns |

## IOC Enrichment

Without API keys: intelligent offline simulation (never fails).  
With API keys (set in `.env`):
- **VirusTotal** — file/IP/domain reputation
- **AbuseIPDB** — IP abuse confidence score  
- **AlienVault OTX** — threat intelligence pulses

## Changes from v2 (Bug Fixes)

1. **Fixed ML predictor** — removed incorrect `StandardScaler` (RF doesn't require scaling); switched to numpy arrays to eliminate sklearn warnings
2. **Fixed route ordering** — `/alerts/stats` now registered before `/alerts/{id}` to prevent 404
3. **Added `upload_id` field** to Alert model for tracing alerts to source files
4. **Added `rule_name` and `username` fields** to Alert model
5. **Fixed IOC lookup** — graceful fallback always works, never raises
6. **Added missing `python-multipart`** dependency for file uploads
7. **Removed `pandas` dependency** from requirements (not needed by ML fix)
