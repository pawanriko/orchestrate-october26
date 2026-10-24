# Ghost Data Still Exists — deletion-audit engine

HackerRank Orchestrate October'26 entry: an AI deletion-audit agent for
Northstar Shop. Given a user's deletion request, it audits every system that
may still hold that user's data and emits an ordered remediation plan.

**Challenge window:** Sat Oct 24, 2026 6:00 PM IST → Sun Oct 25, 2026 6:00 PM IST
**Challenge page:** https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges
**Discord:** https://discord.gg/TzsUaAhPbr
**AI-judge interview:** opens on submit, closes Mon Oct 26, 2026 6:00 AM IST
**Results:** Tue Oct 27, 2026 6:00 PM IST

## What the solution is

A **deterministic, stdlib-only rules engine** (`src/engine.py`). It makes
**zero model calls** — no LLM is in the graded path at all. For each
deletion request it:

1. Resolves the user from current + historical identifiers (audit log).
2. Reconstructs the state of every linked record **at `audit_at`** from the
   evidence corpus (SQL snapshots, JSON exports/bundles, handover TXT, logs,
   and pre-extracted PDF/PNG content).
3. Applies the statement's 15-rule treatment table
   (DELETE / REDACT / ANONYMIZE / RETAIN).
4. Emits steps ordered **FINDING → REMEDIATION → VERIFICATION**, with
   consecutive step numbers, evidence citations on findings and COMPLETE
   verifications, and empty evidence on proposed/future steps.

Output is `output.csv`: exactly 518 rows sorted by `case_id`, columns
`case_id, deletion_status, steps_json`, where `deletion_status` is one of
`COMPLETE` (verification steps only), `INCOMPLETE` (findings + full
remediation + post-fix checks), or `NOT_APPLICABLE` (empty step list).

## How to run it

Requires only Python 3 (standard library). No dependencies to install
(`requirements.txt` is intentionally empty apart from a comment).

```bash
# Full run — reproduces output.csv (518 rows)
python -m src.engine --dataset <dataset>/ \
  --requests <dataset>/deletion_requests.csv --output output.csv

# Sample validation against the 32 sample cases with answers
python3 scripts/validate_samples.py <dataset>/

# Unit tests
python3 -m unittest discover -s tests

# Self-created evaluation cases (7 synthetic cases)
python3 evaluation/self_created_cases.py

# Regenerate / audit the checked-in PDF/PNG extractions
python3 scripts/extract_evidence.py --dataset <dataset>/ --check-only
```

The engine's `--extracted` flag points at `evidence/extracted/` by default
(checked into this package). The only input not in this package is the
dataset directory itself, passed as `--dataset`.

## Design summary

- **Identity resolution:** current + historical identifiers from the audit
  log (e.g. an old email address still resolves to the user). Names are
  never used for matching — they collide across users.
- **State at `audit_at`:** the latest observation at or before `audit_at`
  wins; **evidence beats activity claims**. A DELETE SUCCESS claim is
  overruled by a later failover snapshot showing the record still ACTIVE.
  `reported_status` is treated as a claim, never as truth.
- **Two-phase state:** resources are linked by identifiers first, then
  *all* observations of a linked resource are used — even identifier-free
  ones (e.g. a 404 lookup still describes a linked account).
- **State-driven treatment, not category-driven:** a bare PRESENT record
  (existence-only evidence) earns REPORT_REMAINING + DELETE, while an
  IDENTIFIABLE record (content carries identifiers, including emails inside
  `message_text`) earns REPORT_EXPOSED_PII + REDACT (support/tombstone) or
  ANONYMIZE (analytics). A contact lookup proving existence is not proof
  of identifiability.
- **Tombstones:** a user_id may remain, but name/email/phone/email_hash
  must be stripped; a tombstone still carrying identifiers is redacted.
- **Ordering:** FINDING → REMEDIATION → VERIFICATION; within a phase by
  the statement's operation order, then `system_id`, then `resource_id`.
- **Citation:** findings and COMPLETE verifications cite the latest
  mentioning evidence file at or before `audit_at` (falling back to the
  latest same-system file); proposed remediation and future verification
  steps carry an empty `evidence_id`.
- **Log linkage:** `*_started` / `*_completed` log lines are paired by
  `trace_id`, because identifiers live on the started lines
  (`lookup_key` / `match_key` / `subject_key` / `subject_ref`).
- **Abstention policy:** when the evidence cannot ground a link, the engine
  abstains rather than guesses. A wrong account costs a false step *plus*
  a missing one; a missing step costs only the missing one. This is a
  deliberate, documented choice — see "Known gaps" below. Shared-timestamp
  account collisions (several accounts sharing a reported_at window with
  no usable evidence link) are abstained on, and time-window "batch
  linkage" was tested and rejected: the worker stream is a global queue,
  and batching falsely linked 8 resources to one sample case and flipped
  another case's status.

## Results (reproduced, not claimed)

Against the 32 sample cases with answers (`scripts/validate_samples.py`):

| Metric | Result |
|---|---|
| Status accuracy | **32/32 (100%)** |
| Exact-steps match (status + full ordered steps, incl. evidence) | **18/32 (56.2%)** |
| Field accuracy, positional alignment | 926/1038 (89.2%) |
| Evidence citation on aligned pairs | 100% |

Full-run output (`output.csv`, 518 rows): 317 INCOMPLETE, 197 COMPLETE,
4 NOT_APPLICABLE (case_533/535/540/541 — the Latin-script non-deletion
cases the detector is designed to catch), 2,406 steps total. Mechanical
validation passes: 518 sorted unique rows, valid statuses, consecutive
step numbers, FINDING → REMEDIATION → VERIFICATION order, empty step
lists on NOT_APPLICABLE rows, verification-only steps on COMPLETE rows.
16 unit tests pass; 7/7 self-created synthetic evaluation cases pass.

Full detail: `evaluation/evaluation_report.md`.
Cost: **0 model calls, 0 tokens, $0** — see `evaluation/usage_report.md`.

## Evidence preparation (PDFs and images)

The engine cannot read PDFs or PNGs directly, so their content was
pre-extracted into checked-in files under `evidence/extracted/`:

- **4 PDF documents:** re-extracted offline with `pdftotext -layout`
  (poppler). Deterministic, no model calls. Regenerable via
  `scripts/extract_evidence.py`.
- **11 PNG screenshots:** curated visual transcriptions, checked in as
  text. No OCR engine is installed on the build machine and no vision or
  language model was used for any transcription. The extraction script
  verifies each transcription exists.
- Only **attributable** records become engine observations: a resource is
  emitted only when the document itself ties it to identifiers (header,
  detail panel, owner/selector column). Secondary mentions (other
  customers' queries in activity panels, linked tickets in sidebars) are
  transcribed for human audit but never emitted — free text is full of
  decoy mentions.

Four sources were examined and found to contain **no attributable
records** — documented abstentions, not skipped files:

- `evidence_18` (PDF customer statement): names user_18 but shows no
  deletion-resource ID; a statement number is not a deletion resource.
- `evidence_27` (PDF register): rows keyed by `user_N` with retain-until
  dates in 2033, but no `legal_hold_NNNN` resource ID for any row.
- `evidence_42` (PNG customer-reference screen): shows a retained
  reference for user_17 but displays no `tombstone_NNNN` ID and no direct
  identifier.
- `evidence_46` (PNG object-storage listing): object filenames only, no
  deletion-resource ID and no user identifier anywhere on screen.

Each carries an explicit NO RECORDS note in its checked-in file, so a gap
is never a silent skip. This pass fixed the one sample status miss
(case_07, support_001 in a PDF) and moved exact-steps match from 17/32
to 18/32 with no regressions.

## Known gaps (honest)

- **Null-identifier analytics profiles — unrecoverable by design.**
  Six sample analytics profiles (analytics_9406/5335/1895/4566/4574/6077,
  cases 03/21/25/26/27/28) carry null identifiers in every participant-
  visible source: evidence snapshots, bundle, lookup trace
  (`lookup_key=null`), and activity rows with only a generic note. Order
  linkage, metric/activity fingerprinting, trace-file grouping, and
  numeric-ID patterns were all tested and contradicted by the data
  (full analysis in `docs/decisions.md`). The engine observes them
  correctly as ANONYMIZED with empty identifier sets; only attribution is
  missing. Guessing would cost more than abstaining, so 6 sample
  VERIFY_RECORD_ANONYMIZED steps stay missing.
- **Abstained shared-timestamp accounts.** Sample cases 18/20/22/23/28/
  29/31/32 involve accounts with no usable evidence link in shared
  reported_at windows. The engine abstains rather than assigning the
  wrong account.
- **audit_record_5569/6645 have no participant-visible occurrence.**
  All 11 images were read in full and the corpus was grepped: these two
  audit records appear only in the sample answers' expected steps, never
  in any text evidence, activity row, or image. Their
  VERIFY_RECORD_PRESENT steps are not recoverable by any grounded rule
  found so far.
- **35 zero-step COMPLETE rows are the weakest predictions** in
  `output.csv` (no linked resource, no identifiable account — the engine
  found nothing to verify). They are flagged here and in the evaluation
  report rather than assumed correct.
- **Expired-retention branch is unvalidated.** The engine implements the
  principled rule (a SECURITY_AUDIT_LOG / LEGAL_HOLD_RECORD whose
  retention expired before `audit_at` is treated as a leftover), but no
  record in the visible data expires before any audit_at (all retentions
  are 2031–2034), so no sample exercises the branch.
- **Remaining exact-match loss is missing steps, not wrong steps** (20
  missing steps across the 14 non-exact samples; every predicted finding
  cites the correct evidence file).

## Package contents

- `src/` — the engine (`engine.py`) and package init.
- `scripts/` — sample validator and evidence extraction/audit script.
- `tests/` — unit tests for identity, state-at-audit, ordering,
  tombstones, status decisions, and extraction.
- `evidence/extracted/` — checked-in PDF text + PNG transcriptions and
  machine-readable RECORD lines consumed by the engine.
- `evaluation/` — evaluation report, usage report, and self-created
  synthetic cases.
- `prompts.md` — required prompts file; states plainly that the graded
  path uses no LLM prompts (see that file).
- `docs/decisions.md` — full decision log, including rejected ideas and
  why (the AI-judge interview prep sheet).

## Strategy note

Deterministic core first, AI only where code cannot reach. The samples
showed the core problem is mechanical — parsing, state reconstruction,
fixed rules, fixed ordering — so a debuggable, free, reproducible engine
beats an LLM per case on consistency, and every step it emits can be
traced to a cited evidence file or an explicit abstention.
