"""
Ghost Data Still Exists — Core Data Models

Pydantic-based data contracts for the deletion-audit agent.
All enums and models enforce the exact schema required by the grader.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeletionStatus(str, enum.Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, enum.Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class Operation(str, enum.Enum):
    # Findings
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    # Remediation
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    # Verification
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class State(str, enum.Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class RequiredAction(str, enum.Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


# ---------------------------------------------------------------------------
# Deterministic operation ordering (matches problem statement table order)
# ---------------------------------------------------------------------------

# Within each phase, operations are sorted by their position in this table,
# then by system_id ASC, then by resource_id ASC.
FINDING_OPERATION_ORDER = [
    Operation.REPORT_REMAINING_RECORD,
    Operation.REPORT_EXPOSED_PII,
    Operation.REPORT_ACTIVE_DATA_FLOW,
    Operation.REPORT_RESTORE_RISK,
]

REMEDIATION_OPERATION_ORDER = [
    Operation.DISABLE_DATA_FLOW,
    Operation.BLOCK_RESTORE,
    Operation.DELETE_RECORD,
    Operation.REDACT_RECORD,
    Operation.ANONYMIZE_RECORD,
]

VERIFICATION_OPERATION_ORDER = [
    Operation.VERIFY_RECORD_ABSENT,
    Operation.VERIFY_RECORD_PRESENT,
    Operation.VERIFY_RECORD_REDACTED,
    Operation.VERIFY_RECORD_ANONYMIZED,
    Operation.VERIFY_DATA_FLOW_DISABLED,
    Operation.VERIFY_RESTORE_BLOCKED,
]

OPERATION_ORDER_MAP: dict[Operation, int] = {}
for _idx, _op in enumerate(FINDING_OPERATION_ORDER):
    OPERATION_ORDER_MAP[_op] = _idx
for _idx, _op in enumerate(REMEDIATION_OPERATION_ORDER):
    OPERATION_ORDER_MAP[_op] = _idx
for _idx, _op in enumerate(VERIFICATION_OPERATION_ORDER):
    OPERATION_ORDER_MAP[_op] = _idx


# ---------------------------------------------------------------------------
# Step dataclass
# ---------------------------------------------------------------------------

@dataclass
class Step:
    """One step in the steps_json array."""
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: State
    evidence_id: str  # empty string for remediation/future-verification steps

    def sort_key(self) -> tuple:
        """Return the deterministic sort key for ordering within a phase."""
        op_order = OPERATION_ORDER_MAP.get(self.operation, 999)
        return (op_order, self.system_id, self.resource_id)

    def to_dict(self, step_no: int) -> dict:
        """Serialize to the exact JSON object required by the grader."""
        return {
            "step_no": step_no,
            "phase": self.phase.value,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "state": self.state.value,
            "evidence_id": self.evidence_id,
        }


# ---------------------------------------------------------------------------
# OutputRow dataclass
# ---------------------------------------------------------------------------

@dataclass
class OutputRow:
    """One row of the final output.csv."""
    case_id: str
    deletion_status: DeletionStatus
    steps: list[Step] = field(default_factory=list)

    def steps_json(self) -> str:
        """Serialize steps to the JSON string for CSV output."""
        if self.deletion_status == DeletionStatus.NOT_APPLICABLE:
            return "[]"
        numbered = [s.to_dict(i + 1) for i, s in enumerate(self.steps)]
        return json.dumps(numbered, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Deletion Request (parsed from input CSV)
# ---------------------------------------------------------------------------

@dataclass
class DeletionRequest:
    """One row from deletion_requests.csv."""
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


# ---------------------------------------------------------------------------
# User Identity
# ---------------------------------------------------------------------------

@dataclass
class UserIdentity:
    """One row from user_identities.csv."""
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: str


# ---------------------------------------------------------------------------
# Identity Graph Node — all known identifiers for a user
# ---------------------------------------------------------------------------

@dataclass
class IdentityGraph:
    """All known current and historical identifiers for a user."""
    user_id: str
    name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    all_emails: set[str] = field(default_factory=set)
    all_phones: set[str] = field(default_factory=set)
    all_email_hashes: set[str] = field(default_factory=set)

    def matches_identifier(self, value: str) -> bool:
        """Check if any known identifier matches the given value (case-insensitive for emails)."""
        if not value:
            return False
        val_lower = value.lower()
        if val_lower == self.user_id.lower():
            return True
        if val_lower in {e.lower() for e in self.all_emails}:
            return True
        if value in self.all_phones:
            return True
        if val_lower in {h.lower() for h in self.all_email_hashes}:
            return True
        return False


# ---------------------------------------------------------------------------
# Deletion Rule
# ---------------------------------------------------------------------------

@dataclass
class DeletionRule:
    """One row from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: RequiredAction


# ---------------------------------------------------------------------------
# Evidence File manifest entry
# ---------------------------------------------------------------------------

@dataclass
class EvidenceFileEntry:
    """One row from evidence_files.csv."""
    file_id: str
    file_path: str
    origin: str
    captured_at: str


# ---------------------------------------------------------------------------
# Discovered Record — a record found in evidence that relates to a user
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredRecord:
    """A record discovered in evidence that relates to a specific user."""
    system_id: str
    resource_id: str
    evidence_id: str
    record_type: str  # data_category from deletion_rules
    pii_exposed: bool = False  # True if PII fields are still present
    is_tombstone: bool = False
    restore_allowed: bool = False  # For backup entries
    data_flow_active: bool = False  # For integration connectors
    connector_name: str = ""
    record_absent: bool = False  # True if 404 / not found (account deleted)

    # Raw data for deeper inspection
    raw_data: Optional[dict] = None
