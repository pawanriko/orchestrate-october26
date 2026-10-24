# Prompts

## Honest statement

**The graded solution path uses no LLM prompts.**

The solution in this package is a deterministic, stdlib-only rules engine
(`src/engine.py`). It reads the dataset, reconstructs record state at
`audit_at`, applies the problem statement's 15-rule treatment table, and
writes `output.csv`. It makes no network calls and no model calls, so
there is no prompt that drives the graded run, and none is reproduced
here.

Evidence preparation used no model calls either:

- The 4 PDF documents were extracted offline with `pdftotext -layout`
  (poppler) — a deterministic text-layer extraction, not a prompt.
- The 11 PNG screenshots were transcribed by careful visual reading and
  checked in as text under `evidence/extracted/` (audited by
  `scripts/extract_evidence.py --check-only`). No vision model, OCR
  engine, or language model was used for any transcription.

This file exists because the submission format asks for prompts. Inventing
prompts that were never used would misrepresent the solution, so instead
of fabricated prompt text, this file records the fact plainly: **there
are no prompts in the graded path to disclose.**

## Development assistance (general terms only)

Conversational AI assistance was used during development in the usual
way — discussing the problem statement, reviewing code, and debugging —
but no assistant output was fed into the engine as data, no per-case
prompting was used to produce `output.csv`, and no token counts are
claimed for that assistance because it is not part of the graded run.
The usage report (`evaluation/usage_report.md`) therefore correctly
reports 0 model calls, 0 tokens, and $0 for the run that produced the
submission output.

## What to judge instead

If you are grading prompt quality, there is nothing here to grade — by
design. Judge the engine on `src/engine.py`, the decision log in
`docs/decisions.md` (including rejected ideas and why), and the
reproduction commands in `README.md`.
