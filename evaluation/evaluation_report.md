# Evaluation report — deletion-audit engine ("Ghost Data Still Exists")

## Solution under evaluation

A deterministic, stdlib-only rules engine (`src/engine.py`). For each
deletion request it reconstructs the state of every linked record at
`audit_at` from the evidence corpus (SQL snapshots, JSON exports/bundles,
handover TXT, logs, and pre-extracted PDF/PNG content), applies the
statement's treatment table (DELETE / REDACT / ANONYMIZE / RETAIN), and
emits steps ordered FINDING → REMEDIATION → VERIFICATION. No model is
called by the engine at any point (see `evaluation/usage_report.md`).

Full-run command:

```
python -m src.engine --dataset <dataset>/ \
  --requests <dataset>/deletion_requests.csv --output output.csv
```

## 1. Accuracy against the 32 sample cases

Reproduced with `python3 scripts/validate_samples.py` (plus a step-level
analysis over the same predictions). Status is never wrong.

| Metric | Result |
|---|---|
| Status accuracy | **32/32 (100%)** |
| Exact-steps match (status + full ordered steps, incl. evidence) | **18/32 (56.2%)** |
| Sequence accuracy (full ordered step sequence, incl. evidence) | **18/32 (56.2%)** |
| Sequence accuracy (excluding `evidence_id`) | **18/32 (56.2%)** |
| Field accuracy, positional alignment over min-length pairs | **926/1038 (89.2%)** |
| Step precision (predicted step tuples appearing in expected) | **142/173 (82.1%)** |
| Step recall (expected step tuples predicted) | **142/193 (73.6%)** |

Per-field accuracy (positional):

| Field | Correct / compared | Accuracy |
|---|---|---|
| phase | 173/173 | 100.0% |
| system_id | 142/173 | 82.1% |
| resource_id | 142/173 | 82.1% |
| operation | 148/173 | 85.5% |
| state | 148/173 | 85.5% |
| evidence_id | 173/173 | 100.0% |

Exact-match cases (18): case_01, case_02, case_05, case_06, case_07,
case_08, case_09, case_10, case_11, case_12, case_13, case_14, case_15,
case_16, case_17, case_19, case_24, case_30.

Non-exact cases (14) — predicted vs expected step counts: case_03 (2/3),
case_04 (0/2), case_18 (12/14), case_20 (6/8), case_21 (1/3), case_22
(7/8), case_23 (7/8), case_25 (1/3), case_26 (5/6), case_27 (5/6),
case_28 (4/6), case_29 (13/14), case_31 (2/3), case_32 (4/5). In every
non-exact case the engine predicts *fewer* steps than expected; the
validator counts 20 missing steps overall. No case predicts a wrong
deletion status, and every predicted finding cites the correct evidence
file (evidence_id 100% on aligned pairs).

## 2. Self-created evaluation cases

Seven synthetic cases built in memory (not copied from samples), each
exercising one distinct rule. Runnable check:
`python3 evaluation/self_created_cases.py` — **7/7 pass exactly**
(status + full ordered steps).

| # | Case | Rule exercised | Expected | Actual |
|---|---|---|---|---|
| 1 | tombstone_redact | ACCOUNT_TOMBSTONE with identifiers → REDACT, not DELETE | INCOMPLETE, 4 steps (REPORT_EXPOSED_PII → REDACT_RECORD → VERIFY_RECORD_ABSENT + VERIFY_RECORD_REDACTED) | identical |
| 2 | expired_retention_audit_log | SECURITY_AUDIT_LOG past retention → DELETE, not RETAIN | INCOMPLETE, 4 steps (REPORT_REMAINING_RECORD → DELETE_RECORD → 2× VERIFY_RECORD_ABSENT) | identical |
| 3 | shared_context_support_message | SUPPORT_MESSAGE (shared context) → REDACT, not DELETE | INCOMPLETE, 4 steps (REPORT_EXPOSED_PII → REDACT_RECORD → VERIFY_RECORD_ABSENT + VERIFY_RECORD_REDACTED) | identical |
| 4 | analytics_anonymize | ANALYTICS_PROFILE identifiable → ANONYMIZE | INCOMPLETE, 4 steps (REPORT_EXPOSED_PII → ANONYMIZE_RECORD → VERIFY_RECORD_ABSENT + VERIFY_RECORD_ANONYMIZED) | identical |
| 5 | in_retention_audit_log_complete | SECURITY_AUDIT_LOG in retention → RETAIN, verification only | COMPLETE, 2 steps (VERIFY_RECORD_ABSENT + VERIFY_RECORD_PRESENT, both cited) | identical |
| 6 | non_deletion_text | Explicit keep/continue wording, no deletion intent → NOT_APPLICABLE | NOT_APPLICABLE, 0 steps | identical |
| 7 | classified_non_deletion | CLASSIFY_REQUEST non-deletion account → NOT_APPLICABLE | NOT_APPLICABLE, 0 steps | identical |

## 3. Full 518-case run (output.csv)

| Deletion status | Cases |
|---|---|
| INCOMPLETE | 317 |
| COMPLETE | 197 |
| NOT_APPLICABLE | 4 (case_533, case_535, case_540, case_541 — exactly the 4 Latin non-deletion cases the detector was designed for) |
| **Total** | **518** |

Total steps emitted: 2,406. Step-count distribution is dominated by
6-step (76 cases), 1-step (73), 7-step and 4-step (66 each) outcomes;
39 rows carry 0 steps: 4 NOT_APPLICABLE, and 35 COMPLETE rows where no
resource linked to the user and no account could be identified, so
there is nothing to verify. Those 35 zero-step COMPLETE rows are the
least-confident predictions in the file (see failures below).

Mechanical validation of `output.csv` (all checks pass):
- Exactly 518 data rows, `case_id` unique and sorted (lexicographic,
  matching the sample file's convention: case_100 … case_99).
- Columns exactly `case_id, deletion_status, steps_json`.
- Every `deletion_status` in {COMPLETE, INCOMPLETE, NOT_APPLICABLE}.
- Every `steps_json` parses as JSON; every step has exactly the fields
  `step_no, phase, system_id, resource_id, operation, state, evidence_id`.
- Step numbers are consecutive from 1 within each case.
- Phase order is FINDING → REMEDIATION → VERIFICATION in every case.
- NOT_APPLICABLE rows carry `[]`; COMPLETE rows carry verification
  steps only.

## 4. Failures and improvements (honest)

1. **Null-identifier analytics profiles (largest exact-match loss).**
   Records such as analytics_9406/5335/1895/4566/4574/6077 carry zero
   identifiers in any text evidence, so no participant-side rule can
   link them to their user. Time-clustering, file-order, and
   activity-window assignment were all tested and rejected — each
   contradicted the samples. This is unrecoverable from the supplied
   evidence and accounts for most of the 20 missing steps.
2. **Abstained shared-timestamp accounts.** When several cases share a
   reported_at window and no evidence link distinguishes their accounts
   (cases 18, 20, 28, 29, 31, 32, 22, 23), the engine abstains rather
   than guess: a wrong account costs a false step *plus* a missing one.
   The knock-on effect is visible in case_32, where the account
   verification is absent from the prediction. Activity time-window
   "batch linkage" was tested and removed — the worker stream is a
   global queue, many cases report at round hours, and it falsely
   linked 8 resources to case_11 and flipped case_04 to INCOMPLETE.
3. **Accounts with no text mention at all** (004, 410, 4990): no
   evidence exists to link them, so their cases can only be judged
   from activity claims, which the engine treats as claims, never truth.
4. **Audit records visible only in images (audit_5569, audit_6645):**
   no participant-visible occurrence was found in any evidence file;
   treated as unrecoverable, not guessed.
5. **Four evidence files without extraction** (evidence_18, evidence_27
   PDFs; evidence_42, evidence_46 PNGs): the engine warns loudly
   rather than silently skipping them. None is cited by any sample
   case, so sample accuracy is unaffected; whether they would change
   any full-run case cannot be verified without ground truth.
6. **Zero-step COMPLETE rows (35).** When no resource links to the
   user and no account can be identified, the engine emits COMPLETE
   with no steps — there is nothing to verify. This is the
   "no-evidence" default, and it is the weakest point of the full run:
   if any of those 35 users do have an unlinked account record, the
   true status would be INCOMPLETE. The samples contain no such case
   to calibrate against, so the default is kept and flagged here
   rather than silently assumed correct.
7. **Untested corners, no samples exist:** expired retention for
   LEGAL_HOLD_RECORD (the code path mirrors the audit-log path and is
   covered by a synthetic case only for audit logs), and
   non-deletion requests in non-Latin scripts (the text classifier is
   Latin-script only by design).

Improvements that would actually move the numbers, in order:
- An OCR engine for the PNG screenshots (none is installed on the
  build machine) to replace curated transcriptions and possibly
  recover audit_5569/6645.
- Any participant-visible signal linking null-identifier analytics
  records to users — none has been found; this must be investigated,
  not assumed.
- Nothing else: the status logic is already at 32/32, and the
  remaining exact-match loss is missing evidence, not wrong rules.
  Further rule-tweaking against the samples would risk overfitting
  them.

## 5. Regression checks

- Unit tests: `python3 -m unittest discover -s tests` → **16/16 pass**.
- Sample validator re-run after the full run: status **32/32**,
  exact-steps **18/32** — no regression from the validated state.
- Self-created cases: **7/7 pass**.
