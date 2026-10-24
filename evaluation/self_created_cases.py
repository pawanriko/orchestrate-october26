"""Self-created evaluation cases for the deterministic deletion-audit engine.

These are SYNTHETIC cases, built in memory (no dataset files), each
exercising one distinct rule of the problem statement. They are not
sample cases and their answers are not copied from anywhere: the
expected steps follow directly from the statement's treatment table
(DELETE / REDACT / ANONYMIZE / RETAIN) and the FINDING -> REMEDIATION
-> VERIFICATION ordering.

Run:  python3 evaluation/self_created_cases.py
Exit code 0 only if every case passes exactly (status + full steps).
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.engine import Dataset, Observation, audit_case  # noqa: E402

EMAIL = "synth@example.com"
USER = "user_9001"
AUDIT_AT = "2026-01-20T00:00:00Z"
REPORTED_AT = "2026-01-15T00:00:00Z"
DELETE_TEXT = "Please delete my account and erase all my personal data."
MANIFEST = {"ev_a": {"file_id": "ev_a", "captured_at": "2026-01-10T00:00:00Z"}}


def make_data(observations, classify=()):
    return Dataset(
        rules={"USER_PROFILE": "DELETE", "ACCOUNT_TOMBSTONE": "REDACT",
               "SUPPORT_MESSAGE": "REDACT", "ANALYTICS_PROFILE": "ANONYMIZE",
               "SECURITY_AUDIT_LOG": "RETAIN"},
        identities={USER: {"email": EMAIL, "phone": "", "email_hash": ""}},
        audit_log=[], activity=[], evidence_manifest=MANIFEST,
        observations=observations,
        file_systems={"ev_a": {"account_service", "identity_service",
                               "support_platform", "analytics_platform",
                               "security_service"}},
        classify_non_deletion_accounts=set(classify),
    )


def obs(system_id, resource_id, category, state, when="2026-01-10T00:00:00Z",
        retention=None):
    return Observation(
        file_id="ev_a", observed_at=datetime.fromisoformat(when),
        system_id=system_id, resource_id=resource_id, category=category,
        state=state, identifiers={USER, EMAIL}, retention_until=(
            datetime.fromisoformat(retention) if retention else None))


def account_absent():
    return obs("account_service", "account_synth", "USER_PROFILE", "ABSENT")


def case(email=EMAIL, text=DELETE_TEXT):
    return {"case_id": "synth", "email": email, "audit_at": AUDIT_AT,
            "reported_at": REPORTED_AT, "request_text": text}


def step(no, phase, system_id, resource_id, operation, state, evidence):
    return {"step_no": no, "phase": phase, "system_id": system_id,
            "resource_id": resource_id, "operation": operation,
            "state": state, "evidence_id": evidence}


CASES = []


def register(name, data, expected_status, expected_steps, request=None):
    CASES.append((name, data, expected_status, expected_steps,
                  request or case()))


# 1. Tombstone still carrying identifiers -> REDACT, not DELETE.
register(
    "tombstone_redact",
    make_data([account_absent(),
               obs("identity_service", "tombstone_synth", "ACCOUNT_TOMBSTONE",
                   "IDENTIFIABLE")]),
    "INCOMPLETE",
    [step(1, "FINDING", "identity_service", "tombstone_synth",
          "REPORT_EXPOSED_PII", "PRESENT", "ev_a"),
     step(2, "REMEDIATION", "identity_service", "tombstone_synth",
          "REDACT_RECORD", "REDACTED", ""),
     step(3, "VERIFICATION", "account_service", "account_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", ""),
     step(4, "VERIFICATION", "identity_service", "tombstone_synth",
          "VERIFY_RECORD_REDACTED", "REDACTED", "")],
)

# 2. Security audit log whose retention has EXPIRED -> DELETE (not RETAIN).
register(
    "expired_retention_audit_log",
    make_data([account_absent(),
               obs("security_service", "audit_synth", "SECURITY_AUDIT_LOG",
                   "PRESENT", retention="2026-01-05T00:00:00Z")]),
    "INCOMPLETE",
    [step(1, "FINDING", "security_service", "audit_synth",
          "REPORT_REMAINING_RECORD", "PRESENT", "ev_a"),
     step(2, "REMEDIATION", "security_service", "audit_synth",
          "DELETE_RECORD", "ABSENT", ""),
     step(3, "VERIFICATION", "account_service", "account_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", ""),
     step(4, "VERIFICATION", "security_service", "audit_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", "")],
)

# 3. Shared-context support message -> REDACT, not DELETE.
register(
    "shared_context_support_message",
    make_data([account_absent(),
               obs("support_platform", "support_synth", "SUPPORT_MESSAGE",
                   "IDENTIFIABLE")]),
    "INCOMPLETE",
    [step(1, "FINDING", "support_platform", "support_synth",
          "REPORT_EXPOSED_PII", "PRESENT", "ev_a"),
     step(2, "REMEDIATION", "support_platform", "support_synth",
          "REDACT_RECORD", "REDACTED", ""),
     step(3, "VERIFICATION", "account_service", "account_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", ""),
     step(4, "VERIFICATION", "support_platform", "support_synth",
          "VERIFY_RECORD_REDACTED", "REDACTED", "")],
)

# 4. Analytics profile still identifiable -> ANONYMIZE, not DELETE/REDACT.
register(
    "analytics_anonymize",
    make_data([account_absent(),
               obs("analytics_platform", "analytics_synth",
                   "ANALYTICS_PROFILE", "IDENTIFIABLE")]),
    "INCOMPLETE",
    [step(1, "FINDING", "analytics_platform", "analytics_synth",
          "REPORT_EXPOSED_PII", "PRESENT", "ev_a"),
     step(2, "REMEDIATION", "analytics_platform", "analytics_synth",
          "ANONYMIZE_RECORD", "ANONYMIZED", ""),
     step(3, "VERIFICATION", "account_service", "account_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", ""),
     step(4, "VERIFICATION", "analytics_platform", "analytics_synth",
          "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "")],
)

# 5. Audit log still IN retention -> RETAIN: verification only, COMPLETE.
register(
    "in_retention_audit_log_complete",
    make_data([account_absent(),
               obs("security_service", "audit_synth", "SECURITY_AUDIT_LOG",
                   "PRESENT", retention="2026-06-01T00:00:00Z")]),
    "COMPLETE",
    [step(1, "VERIFICATION", "account_service", "account_synth",
          "VERIFY_RECORD_ABSENT", "ABSENT", "ev_a"),
     step(2, "VERIFICATION", "security_service", "audit_synth",
          "VERIFY_RECORD_PRESENT", "PRESENT", "ev_a")],
)

# 6. Explicit keep/continue request, no deletion wording -> NOT_APPLICABLE.
register(
    "non_deletion_text",
    make_data([account_absent()]),
    "NOT_APPLICABLE", [],
    request=case(text="Please leave the account active as it is, "
                      "I want to continue using it."),
)

# 7. Deletion wording, but the account was classified non-deletion
#    (CLASSIFY_REQUEST path) -> NOT_APPLICABLE.
register(
    "classified_non_deletion",
    make_data([account_absent()], classify=("account_synth",)),
    "NOT_APPLICABLE", [],
)


def main() -> int:
    failures = 0
    for name, data, exp_status, exp_steps, req in CASES:
        status, steps = audit_case(data, req, set())
        if status == exp_status and steps == exp_steps:
            print(f"PASS {name}: {status} ({len(steps)} steps)")
        else:
            failures += 1
            print(f"FAIL {name}: got {status} {steps}")
            print(f"     expected {exp_status} {exp_steps}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} self-created cases pass")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
