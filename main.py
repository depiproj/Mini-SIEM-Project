
import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import API_TITLE, API_VERSION, DEBUG, BASE_DIR, CORS_ORIGINS, RETENTION_DAYS
from models.database import init_db
from api.ingestion import router as ingestion_router
from api.dashboard import router as dashboard_router
from api.analyze import router as analyze_router
from api.upload import router as upload_router

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

FRONTEND_DIR = BASE_DIR / "frontend"
INDEX_FILE   = FRONTEND_DIR / "index.html"
STATIC_DIR   = FRONTEND_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Mini-SIEM v%s — initialising database …", API_VERSION)
    await init_db()
    logger.info("Database ready.")

    try:
        from ml_engine.predictor import _load_model
        _load_model()
    except Exception as e:
        logger.warning("ML model pre-load skipped: %s", e)

    retention_task = None
    if RETENTION_DAYS > 0:
        from services.retention import retention_loop
        retention_task = asyncio.create_task(retention_loop(RETENTION_DAYS))
        logger.info("Retention job started (purging data older than %d days).", RETENTION_DAYS)
    else:
        logger.info("Retention job disabled (RETENTION_DAYS=0).")

    yield

    if retention_task is not None:
        retention_task.cancel()
    logger.info("Shutting down Mini-SIEM.")


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=(
        "Mini-SIEM v3 — Automated security event ingestion, detection, and alerting. "
        "Upload log files (Syslog, Apache, Auth, Windows), get automatic alerts "
        "with MITRE ATT&CK mappings, IOC enrichment, and ML-based detection."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info("CORS allowed origins: %s", CORS_ORIGINS)

app.include_router(ingestion_router)
app.include_router(dashboard_router)
app.include_router(analyze_router)
app.include_router(upload_router)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def index():
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)
    return JSONResponse({"status": "ok", "docs": "/docs"})


@app.get("/health", tags=["System"], summary="Health check")
async def health() -> dict:
    from config import ML_ENABLED, IOC_LOOKUP_ENABLED
    return {
        "status": "ok",
        "version": API_VERSION,
        "ml_enabled": ML_ENABLED,
        "ioc_live_lookup": IOC_LOOKUP_ENABLED,
        "frontend_ready": INDEX_FILE.exists(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)