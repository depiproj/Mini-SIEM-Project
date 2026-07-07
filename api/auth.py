"""
api/auth.py — Simple API-key authentication dependency.

Every request to a protected router must include a header:

    X-API-Key: <value of API_KEY from .env>

If API_KEY is left blank in the environment, auth is disabled and a warning
is logged once at startup — this keeps local/dev usage frictionless while
making it obvious that production deployments must set a real key.

This is intentionally simple (a single shared secret, not per-user tokens
or OAuth) — enough to stop the API being wide open on the internet. If you
need per-analyst accounts/roles, replace this with real user auth.
"""
import logging
import secrets

from fastapi import Header, HTTPException, status

from config import API_KEY

logger = logging.getLogger(__name__)

_warned = False


def _warn_once_if_disabled() -> None:
    global _warned
    if not API_KEY and not _warned:
        logger.warning(
            "API_KEY is not set — all endpoints are UNAUTHENTICATED. "
            "Set API_KEY in your .env before exposing this service."
        )
        _warned = True


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency — raises 401 if the API key is missing/incorrect."""
    _warn_once_if_disabled()

    if not API_KEY:
        # No key configured → auth disabled (dev mode).
        return

    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Provide it via the 'X-API-Key' header.",
        )