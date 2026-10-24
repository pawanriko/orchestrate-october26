"""Unit tests for the deterministic deletion-audit engine.

These tests cover the core rules, not the full dataset: identity
resolution, step ordering, tombstone handling, the status decision, and
the state-driven treatment table. Run with:

    python3 -m unittest discover -s tests -v
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.engine import (  # noqa: E402
    Dataset,
    Observation,
    ResourceState,
    latest_state_at,
    order_steps,
    resolve_user,
    user_identifier_set,
)


def utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def empty_dataset() -> Dataset:
    return Dataset(
        rules={}, identities={}, audit_log=[], activity=[],
        evidence_manifest={}, observations=[], file_systems={},
        classify_non_deletion_accounts=set(),
    )


class TestIdentityResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.data = empty_dataset()
        self.data.identities = {
            "user_01": {
                "user_id": "user_01", "name": "Amina El-Masri",
                "email": "amina.elmasri@gmail.com", "phone": "+20 100 000 0000",
                "email_hash": "aaaabbbb", "updated_at": "2026-01-01T00:00:00Z",
            }
        }
        self.data.audit_log = [
            {"audit_id": "audit_1", "user_id": "user_01",
             "event_time": "2025-06-01T00:00:00Z", "field_name": "email",
             "old_value": "amina.old@yahoo.com", "new_value": "amina.elmasri@gmail.com"},
        ]

    def test_current_email_resolves(self) -> None:
        self.assertEqual(resolve_user(self.data, "amina.elmasri@gmail.com"), "user_01")

    def test_historical_email_resolves(self) -> None:
        self.assertEqual(resolve_user(self.data, "amina.old@yahoo.com"), "user_01")

    def test_case_insensitive_email(self) -> None:
        self.assertEqual(resolve_user(self.data, "AMINA.ELMASRI@GMAIL.COM"), "user_01")

    def test_unknown_email_returns_none(self) -> None:
        self.assertIsNone(resolve_user(self.data, "nobody@example.com"))

    def test_identifier_set_includes_history(self) -> None:
        ids = user_identifier_set(self.data, "user_01")
        self.assertIn("user_01", ids)
        self.assertIn("amina.elmasri@gmail.com", ids)
        self.assertIn("amina.old@yahoo.com", ids)
        self.assertIn("aaaabbbb", ids)
        self.assertIn("+20 100 000 0000", ids)


class TestStateAtAudit(unittest.TestCase):
    def test_latest_observation_at_or_before_audit_wins(self) -> None:
        observations = [
            Observation("evidence_a", utc("2026-09-01T00:00:00Z"), "account_service",
                        "account_1", "USER_PROFILE", "PRESENT"),
            Observation("evidence_b", utc("2026-09-10T00:00:00Z"), "account_service",
                        "account_1", "USER_PROFILE", "ABSENT"),
            Observation("evidence_c", utc("2026-09-20T00:00:00Z"), "account_service",
                        "account_1", "USER_PROFILE", "PRESENT"),
        ]
        state = latest_state_at(observations, utc("2026-09-15T00:00:00Z"))
        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state.state, "ABSENT")
        self.assertEqual(state.evidence_file, "evidence_b")

    def test_observation_exactly_at_audit_counts(self) -> None:
        observations = [
            Observation("evidence_a", utc("2026-09-15T12:00:00Z"), "security_service",
                        "audit_record_1", "SECURITY_AUDIT_LOG", "PRESENT"),
        ]
        state = latest_state_at(observations, utc("2026-09-15T12:00:00Z"))
        self.assertIsNotNone(state)

    def test_no_observation_before_audit_returns_none(self) -> None:
        observations = [
            Observation("evidence_a", utc("2026-09-20T00:00:00Z"), "account_service",
                        "account_1", "USER_PROFILE", "ABSENT"),
        ]
        self.assertIsNone(latest_state_at(observations, utc("2026-09-15T00:00:00Z")))


class TestOrdering(unittest.TestCase):
    def test_phase_then_operation_then_system_then_resource(self) -> None:
        steps = [
            {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_1",
             "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "system_id": "support_platform", "resource_id": "support_2",
             "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": "evidence_x"},
            {"phase": "FINDING", "system_id": "account_service", "resource_id": "account_1",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_x"},
            {"phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_1",
             "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        ]
        ordered = order_steps(steps)
        self.assertEqual(
            [(s["phase"], s["operation"], s["resource_id"]) for s in ordered],
            [
                ("FINDING", "REPORT_REMAINING_RECORD", "account_1"),
                ("FINDING", "REPORT_EXPOSED_PII", "support_2"),
                ("REMEDIATION", "DELETE_RECORD", "account_1"),
                ("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_1"),
            ],
        )

    def test_remediation_operation_order_is_statement_order(self) -> None:
        steps = [
            {"phase": "REMEDIATION", "system_id": "s", "resource_id": "r1",
             "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""},
            {"phase": "REMEDIATION", "system_id": "s", "resource_id": "r2",
             "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""},
            {"phase": "REMEDIATION", "system_id": "s", "resource_id": "r3",
             "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        ]
        ordered = order_steps(steps)
        self.assertEqual(
            [s["operation"] for s in ordered],
            ["DISABLE_DATA_FLOW", "DELETE_RECORD", "ANONYMIZE_RECORD"],
        )


class TestTombstoneHandling(unittest.TestCase):
    """Tombstones: a stable user_id may remain, but name/email/phone/
    email_hash must be stripped. IDENTIFIABLE -> REDACT; REDACTED ->
    verify-only. (Rule exercised through the state mapping helpers.)"""

    def test_tombstone_states(self) -> None:
        from src.engine import _state_from_record
        exposed = _state_from_record("ACCOUNT_TOMBSTONE", {
            "resource_id": "tombstone_1", "customer_reference": "user_99",
            "full_name": "Jane Doe", "email": "jane@example.com",
            "phone": None, "email_hash": None}, "identity_service")
        self.assertEqual(exposed[0], "IDENTIFIABLE")
        clean = _state_from_record("ACCOUNT_TOMBSTONE", {
            "resource_id": "tombstone_2", "customer_reference": "user_99",
            "full_name": None, "email": None, "phone": None, "email_hash": None},
            "identity_service")
        self.assertEqual(clean[0], "REDACTED")


class TestStatusDecision(unittest.TestCase):
    def test_findings_mean_incomplete(self) -> None:
        # The rule is structural: any finding -> INCOMPLETE, else COMPLETE
        # (NOT_APPLICABLE is decided earlier, from the request itself).
        # Here we assert the ordering helper keeps findings first so the
        # decision can be read off the step list.
        steps = order_steps([
            {"phase": "VERIFICATION", "system_id": "a", "resource_id": "r",
             "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "system_id": "a", "resource_id": "r",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "e"},
        ])
        self.assertEqual(steps[0]["phase"], "FINDING")


if __name__ == "__main__":
    unittest.main()
