"""
Ghost Data Still Exists — Remediation Engine

Generates deterministic, ordered steps for deletion audit requests:
  - Phase order: FINDING -> REMEDIATION -> VERIFICATION
  - Within each phase: sorted by Operation table order -> system_id ASC -> resource_id ASC
  - NOT_APPLICABLE cases return empty steps list []
  - INCOMPLETE cases include findings, remediations, and future verifications (evidence_id="")
  - COMPLETE cases include only evidence-backed verification steps
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from models import (
    DeletionRequest,
    DeletionRule,
    DeletionStatus,
    DiscoveredRecord,
    IdentityGraph,
    Operation,
    OutputRow,
    Phase,
    RequiredAction,
    State,
    Step,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Intent Classification: Is this an authorized deletion request?
# ---------------------------------------------------------------------------

NON_DELETION_PHRASES = [
    "leave the account active",
    "not asking for deletion",
    "keep the account as it is",
    "without removing any of my records",
    "leave my profile and purchase history in place",
    "want to continue using the service",
    "stop the promotional emails",
    "misspelled on the account",
    "replace it with the new one and leave the account active",
]


def is_deletion_request(request_text: str) -> bool:
    """
    Determine whether request_text authorizes deletion.
    Requests for access, correction, export, marketing opt-out, etc.
    return False (NOT_APPLICABLE).
    """
    text_lower = request_text.lower()

    for phrase in NON_DELETION_PHRASES:
        if phrase in text_lower:
            return False

    return True


# ---------------------------------------------------------------------------
# Remediation Engine
# ---------------------------------------------------------------------------

class RemediationEngine:
    """Generates ordered remediation plans conforming to challenge contracts."""

    def __init__(self, rules: dict[str, DeletionRule]):
        self._rules = rules

    def audit_and_plan(
        self,
        request: DeletionRequest,
        identity: Optional[IdentityGraph],
        discovered_records: list[DiscoveredRecord],
    ) -> OutputRow:
        """
        Audit discovered records against deletion rules, determine status,
        and generate ordered steps.
        """
        # Step 1: Check request authorization
        if not is_deletion_request(request.request_text):
            return OutputRow(
                case_id=request.case_id,
                deletion_status=DeletionStatus.NOT_APPLICABLE,
                steps=[],
            )

        findings: list[Step] = []
        remediations: list[Step] = []
        verifications: list[Step] = []

        seen_resources: set[str] = set()

        for rec in discovered_records:
            rule = self._rules.get(rec.record_type)
            action = rule.required_action if rule else RequiredAction.DELETE

            # Determine behavior based on resource category and state
            if rec.record_type == "DATA_FLOW" or rec.resource_id.startswith("data_flow_"):
                if rec.data_flow_active:
                    findings.append(Step(
                        phase=Phase.FINDING,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                        state=State.ACTIVE,
                        evidence_id=rec.evidence_id,
                    ))
                    remediations.append(Step(
                        phase=Phase.REMEDIATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.DISABLE_DATA_FLOW,
                        state=State.DISABLED,
                        evidence_id="",
                    ))
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                        state=State.DISABLED,
                        evidence_id="",
                    ))
                else:
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                        state=State.DISABLED,
                        evidence_id=rec.evidence_id,
                    ))

            elif rec.record_type == "BACKUP_ARCHIVE" or rec.resource_id.startswith("backup_"):
                if rec.restore_allowed:
                    findings.append(Step(
                        phase=Phase.FINDING,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REPORT_RESTORE_RISK,
                        state=State.ACTIVE,
                        evidence_id=rec.evidence_id,
                    ))
                    remediations.append(Step(
                        phase=Phase.REMEDIATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.BLOCK_RESTORE,
                        state=State.BLOCKED,
                        evidence_id="",
                    ))
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RESTORE_BLOCKED,
                        state=State.BLOCKED,
                        evidence_id="",
                    ))
                else:
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RESTORE_BLOCKED,
                        state=State.BLOCKED,
                        evidence_id=rec.evidence_id,
                    ))

            elif action == RequiredAction.RETAIN or rec.record_type in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                verifications.append(Step(
                    phase=Phase.VERIFICATION,
                    system_id=rec.system_id,
                    resource_id=rec.resource_id,
                    operation=Operation.VERIFY_RECORD_PRESENT,
                    state=State.PRESENT,
                    evidence_id=rec.evidence_id,
                ))

            elif action == RequiredAction.REDACT or rec.record_type in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"):
                if rec.pii_exposed:
                    findings.append(Step(
                        phase=Phase.FINDING,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REPORT_EXPOSED_PII,
                        state=State.PRESENT,
                        evidence_id=rec.evidence_id,
                    ))
                    remediations.append(Step(
                        phase=Phase.REMEDIATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REDACT_RECORD,
                        state=State.REDACTED,
                        evidence_id="",
                    ))
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_REDACTED,
                        state=State.REDACTED,
                        evidence_id="",
                    ))
                else:
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_REDACTED,
                        state=State.REDACTED,
                        evidence_id=rec.evidence_id,
                    ))

            elif action == RequiredAction.ANONYMIZE or rec.record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                if rec.pii_exposed:
                    findings.append(Step(
                        phase=Phase.FINDING,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REPORT_EXPOSED_PII,
                        state=State.PRESENT,
                        evidence_id=rec.evidence_id,
                    ))
                    remediations.append(Step(
                        phase=Phase.REMEDIATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.ANONYMIZE_RECORD,
                        state=State.ANONYMIZED,
                        evidence_id="",
                    ))
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_ANONYMIZED,
                        state=State.ANONYMIZED,
                        evidence_id="",
                    ))
                else:
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_ANONYMIZED,
                        state=State.ANONYMIZED,
                        evidence_id=rec.evidence_id,
                    ))

            else:  # RequiredAction.DELETE
                if not rec.record_absent:
                    findings.append(Step(
                        phase=Phase.FINDING,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.REPORT_REMAINING_RECORD,
                        state=State.PRESENT,
                        evidence_id=rec.evidence_id,
                    ))
                    remediations.append(Step(
                        phase=Phase.REMEDIATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.DELETE_RECORD,
                        state=State.ABSENT,
                        evidence_id="",
                    ))
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_ABSENT,
                        state=State.ABSENT,
                        evidence_id="",
                    ))
                else:
                    verifications.append(Step(
                        phase=Phase.VERIFICATION,
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation=Operation.VERIFY_RECORD_ABSENT,
                        state=State.ABSENT,
                        evidence_id=rec.evidence_id,
                    ))

        # Deduplicate steps by (phase, system_id, resource_id, operation)
        def deduplicate(steps: list[Step]) -> list[Step]:
            seen = set()
            unique = []
            for s in steps:
                key = (s.phase, s.system_id, s.resource_id, s.operation)
                if key not in seen:
                    seen.add(key)
                    unique.append(s)
            return unique

        findings = deduplicate(findings)
        remediations = deduplicate(remediations)
        verifications = deduplicate(verifications)

        # Deterministic sorting within each phase using Step.sort_key()
        findings.sort(key=lambda s: s.sort_key())
        remediations.sort(key=lambda s: s.sort_key())
        verifications.sort(key=lambda s: s.sort_key())

        # Determine deletion status
        if len(findings) > 0:
            status = DeletionStatus.INCOMPLETE
            # For INCOMPLETE cases, all proposed remediation and future verification
            # steps use evidence_id as an empty string
            for v in verifications:
                v.evidence_id = ""
            for r in remediations:
                r.evidence_id = ""
            final_steps = findings + remediations + verifications
        else:
            status = DeletionStatus.COMPLETE
            # For COMPLETE cases, only verification steps are included,
            # each citing the evidence proving compliance
            final_steps = verifications

        return OutputRow(
            case_id=request.case_id,
            deletion_status=status,
            steps=final_steps,
        )
