
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_MIN_SAMPLES_FOR_ML = 4  # below this, IsolationForest results aren't meaningful

FEATURE_NAMES = [
    "total_events",
    "failed_logins",
    "distinct_usernames",
    "distinct_dest_ips",
    "distinct_event_types",
    "events_per_minute",
]


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def compute_ip_features(events: list[dict]) -> dict[str, dict]:
    """
    Aggregate real per-source-IP behavioral features from parsed log events.
    Returns {ip: {feature_name: value}} for every non-empty source_ip seen.
    """
    by_ip: dict[str, list[dict]] = {}
    for e in events:
        ip = e.get("source_ip")
        if not ip or ip == "0.0.0.0":
            continue
        by_ip.setdefault(ip, []).append(e)

    features: dict[str, dict] = {}
    for ip, evts in by_ip.items():
        failed = sum(1 for e in evts if e.get("action") == "login_failure")
        usernames = {e.get("username") for e in evts if e.get("username")}
        dests = {e.get("dest_ip") for e in evts if e.get("dest_ip")}
        event_types = {e.get("event_type") for e in evts if e.get("event_type")}

        timestamps = sorted(t for t in (_parse_ts(e.get("timestamp")) for e in evts) if t)
        if len(timestamps) >= 2:
            duration_seconds = max((timestamps[-1] - timestamps[0]).total_seconds(), 1.0)
        else:
            duration_seconds = 1.0
        events_per_minute = len(evts) / max(duration_seconds / 60.0, 1 / 60.0)

        features[ip] = {
            "total_events": float(len(evts)),
            "failed_logins": float(failed),
            "distinct_usernames": float(len(usernames)),
            "distinct_dest_ips": float(len(dests)),
            "distinct_event_types": float(len(event_types)),
            "events_per_minute": float(round(events_per_minute, 3)),
        }
    return features


def _statistical_fallback(features: dict[str, dict]) -> dict[str, dict]:
    """Used when there aren't enough distinct IPs for IsolationForest to be meaningful."""
    results = {}
    for ip, f in features.items():
        is_anomalous = (
            f["failed_logins"] >= 5
            or f["distinct_usernames"] >= 3
            or f["distinct_dest_ips"] >= 8
        )
        results[ip] = {
            "prediction": "Anomalous" if is_anomalous else "Normal",
            "is_malicious": is_anomalous,
            "method": "statistical_fallback",
            "note": f"Only {len(features)} distinct source IP(s) in this batch — "
                    f"too few for a meaningful IsolationForest fit (need >= {_MIN_SAMPLES_FOR_ML}). "
                    f"Used a fixed-threshold rule on real behavioral features instead.",
        }
    return results


def score_ip_behavior(events: list[dict]) -> dict[str, dict]:
    """
    Compute a genuine anomaly score per source IP from real log behavior.
    Returns {ip: {"prediction", "is_malicious", "method", "anomaly_score"?}}.
    """
    features = compute_ip_features(events)
    if not features:
        return {}

    if len(features) < _MIN_SAMPLES_FOR_ML:
        return _statistical_fallback(features)

    try:
        from sklearn.ensemble import IsolationForest
    except Exception as e:
        logger.warning("scikit-learn IsolationForest unavailable (%s) — using statistical fallback.", e)
        return _statistical_fallback(features)

    ips = list(features.keys())
    X = np.array([[features[ip][f] for f in FEATURE_NAMES] for ip in ips])

    try:
        model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        model.fit(X)
        raw_scores = model.decision_function(X)   # higher = more normal
        predictions = model.predict(X)              # -1 = anomaly, 1 = normal
    except Exception as e:
        logger.warning("IsolationForest fit/predict failed (%s) — using statistical fallback.", e)
        return _statistical_fallback(features)

    results = {}
    for ip, raw_score, pred in zip(ips, raw_scores, predictions):
        is_anomalous = bool(pred == -1)
        results[ip] = {
            "prediction": "Anomalous" if is_anomalous else "Normal",
            "is_malicious": is_anomalous,
            "method": "isolation_forest",
            "anomaly_score": round(float(-raw_score), 4),  # flip sign: higher = more anomalous
        }
    return results