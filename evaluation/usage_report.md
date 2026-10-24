# Usage report — deletion-audit engine ("Ghost Data Still Exists")

## Graded run (the run that produced `output.csv`)

The graded run is fully deterministic. The engine (`src/engine.py`,
stdlib-only) reads the dataset, applies fixed rules, and writes
`output.csv`. It makes **no network calls and no model calls**.

| Item | Value |
|---|---|
| Model providers used | None |
| Model names used | None |
| Number of model calls | **0** |
| Input tokens | **0** |
| Output tokens | **0** |
| Total tokens | **0** |
| Average tokens per request (518 requests) | **0** |
| Total cost | **$0** |

Reproduction command:

```
python -m src.engine --dataset <dataset>/ \
  --requests <dataset>/deletion_requests.csv --output output.csv
```

## Evidence preparation (PDF / image pass)

The engine cannot read PDFs or PNGs directly, so their content was
pre-extracted into checked-in RECORD files under `evidence/extracted/`
(regenerable/auditable via `scripts/extract_evidence.py`):

| Source | Method | Model calls |
|---|---|---|
| 4 PDF documents | Offline `pdftotext -layout` (poppler), deterministic | 0 |
| 11 PNG screenshots | Curated human visual transcription, checked in as text and verified by `scripts/extract_evidence.py --check-only` | 0 |

No OCR engine is installed on the build machine, and no vision or
language model was used for any transcription. Four evidence files
(evidence_18, evidence_27 PDFs; evidence_42, evidence_46 PNGs) have no
extraction; the engine prints a loud warning for each instead of
silently skipping it.

## Development-time assistance

The code, validators, and reports in this repository were written with
AI assistance during development. That assistance is **not** part of
the solution's runtime and made no calls on behalf of the graded run:
the solution itself issued zero model calls, consumed zero tokens, and
cost $0, as reported above. No token counts for development sessions
are claimed here because none were metered or verifiable; inventing
them would make this report less truthful, not more.

## Keys and secrets

None. No API keys, credentials, or secrets were used, stored, or
transmitted anywhere in this solution.
