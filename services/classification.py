"""
services/classification.py — Severity Classification Engine.

Responsibilities
────────────────
1. Validate that the severity in the incoming event is one of the four
   allowed levels.
2. Apply override rules: if the event_type itself implies a higher severity
   than what was reported, escalate automatically (defence-in-depth).
3. Assign a numeric priority score (used for sorting in the dashboard).
"""
import logging
from schemas.event import EventPayload, VALID_SEVERITIES

logger = logging.getLogger(__name__)

# ── Severity ordering (higher number = more critical) ─────────────────────────
SEVERITY_RANK: dict[str, int] = {
    "Low":      1,
    "Medium":   2,
    "High":     3,
    "Critical": 4,
}

# ── Auto-escalation rules ─────────────────────────────────────────────────────
# If the event_type keyword is found in the event, the severity is raised to at
# least the mapped level, even if the sender reported something lower.
ESCALATION_RULES: dict[str, str] = {
    "ransomware":          "Critical",
    "data_exfiltration":   "Critical",
    "privilege_escalation":"Critical",
    "rootkit":             "Critical",
    "c2_communication":    "Critical",
    "sql_injection":       "High",
    "brute_force":         "High",
    "lateral_movement":    "High",
    "port_scan":           "Medium",
    "failed_login":        "Low",
}


class ClassificationResult:
    """Holds the final severity and an optional audit note."""
    __slots__ = ("severity", "priority", "escalated", "note")

    def __init__(self, severity: str, escalated: bool = False, note: str = ""):
        self.severity  = severity
        self.priority  = SEVERITY_RANK[severity]
        self.escalated = escalated
        self.note      = note

    def __repr__(self) -> str:
        tag = " [ESCALATED]" if self.escalated else ""
        return f"<ClassificationResult severity={self.severity}{tag}>"


def classify_event(event: EventPayload) -> ClassificationResult:
    """
    Main classification entry-point.

    Steps:
      1. Validate the reported severity (Pydantic already did this, but we
         keep the check here to make the service independently testable).
      2. Scan the event_type for escalation triggers.
      3. Return the final severity, escalating when necessary.
    """
    reported = event.severity.strip().capitalize()

    # Step 1 — validate (belt-and-suspenders after Pydantic)
    if reported not in VALID_SEVERITIES:
        logger.warning("Unrecognised severity '%s'. Defaulting to 'Medium'.", reported)
        reported = "Medium"

    # Step 2 — check escalation rules against event_type
    event_key = event.event_type.lower().replace(" ", "_")
    escalated_to: str | None = None

    for keyword, minimum_severity in ESCALATION_RULES.items():
        if keyword in event_key:
            if SEVERITY_RANK[minimum_severity] > SEVERITY_RANK[reported]:
                escalated_to = minimum_severity
                break   # first matching rule wins (most specific first)

    if escalated_to:
        note = (
            f"Auto-escalated from '{reported}' to '{escalated_to}' "
            f"due to event_type keyword match: '{event.event_type}'."
        )
        logger.info(note)
        return ClassificationResult(severity=escalated_to, escalated=True, note=note)

    return ClassificationResult(severity=reported)
