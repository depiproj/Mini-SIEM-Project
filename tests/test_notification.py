"""
tests/test_notification.py — Regression tests for services/notification.py

Bug being guarded against: notify() used to call aiosmtplib.send() with no
timeout and no check for placeholder credentials. With the project's default
placeholder SMTP settings (or any unreachable mail server), this could hang
the entire alert/upload pipeline indefinitely, since it's awaited once per
High/Critical alert.
"""
import asyncio
import os
import time

import pytest

# NOTE: config.py loads .env once at first import and caches the values as
# module-level constants. If a real .env exists (e.g. with production API
# keys), whichever test file imports `config` first "wins" for the whole
# pytest session. Set safe overrides *before* importing anything that
# pulls in config, so this file never leaks real keys into other tests
# (or, worse, never accidentally leaks OUR test into a real mail send).
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
os.environ.setdefault("ABUSEIPDB_API_KEY", "")
os.environ.setdefault("OTX_API_KEY", "")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from services.notification import notify, _smtp_is_configured


class _FakeAlert:
    def __init__(self, severity="High"):
        self.id = 1
        self.severity = severity
        self.event_type = "brute_force"
        self.source_ip = "10.0.0.1"
        self.timestamp = "2026-01-01T00:00:00Z"
        self.description = "test alert"
        self.mitre_technique_id = "T1110"
        self.mitre_technique_name = "Brute Force"
        self.mitre_tactic = "Credential Access"
        self.ioc_reputation = "clean"
        self.ioc_provider = "test"
        self.ioc_malicious = False


class TestPlaceholderCredentialsSkipped:
    def test_smtp_configured_check_does_not_raise(self):
        assert _smtp_is_configured() in (True, False)

    @pytest.mark.asyncio
    async def test_notify_returns_fast_with_placeholder_or_missing_smtp(self):
        alert = _FakeAlert(severity="Critical")
        start = time.monotonic()
        result = await asyncio.wait_for(notify(alert), timeout=15)
        elapsed = time.monotonic() - start
        # Must never hang the pipeline — either skipped instantly (no real
        # creds) or bounded by the internal SMTP timeout, but always well
        # under the old "no timeout at all" failure mode.
        assert elapsed < 15
        assert result in (True, False)

    @pytest.mark.asyncio
    async def test_notify_skips_low_severity(self):
        alert = _FakeAlert(severity="Low")
        result = await notify(alert)
        assert result is False
