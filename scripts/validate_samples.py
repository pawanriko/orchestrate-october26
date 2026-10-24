"""Validate the deterministic engine against the 32 sample cases.

Usage:
    python scripts/validate_samples.py <dataset_dir>

The dataset directory is always passed explicitly so this script never
depends on a machine-specific path.

Prints status accuracy, exact-steps match rate, and a per-case diff of
field-level mismatches. Exits 0 even on mismatches (this is a report,
not a gate) — the numbers are what matter.
"""

import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.engine import load_dataset, audit_case  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python scripts/validate_samples.py <dataset_dir>",
              file=sys.stderr)
        return 2
    dataset_dir = Path(sys.argv[1])
    data = load_dataset(dataset_dir)
    with open(dataset_dir / "sample_deletion_requests.csv", newline="") as handle:
        cases = list(csv.DictReader(handle))
    with open(dataset_dir / "sample_output.csv", newline="") as handle:
        expected = {row["case_id"]: row for row in csv.DictReader(handle)}

    used: set[str] = set()
    status_ok = 0
    exact_ok = 0
    field_mismatches = Counter()
    for case in sorted(cases, key=lambda c: c["case_id"]):
        case_id = case["case_id"]
        status, steps = audit_case(data, case, used)
        exp = expected[case_id]
        exp_steps = json.loads(exp["steps_json"])
        status_match = status == exp["deletion_status"]
        status_ok += status_match
        got = [
            {k: s[k] for k in ("step_no", "phase", "system_id", "resource_id",
                               "operation", "state", "evidence_id")}
            for s in steps
        ]
        exact = status_match and got == exp_steps
        exact_ok += exact
        if not exact:
            print(f"\n== {case_id}: got {status} ({len(got)} steps), "
                  f"expected {exp['deletion_status']} ({len(exp_steps)} steps)")
            for i in range(max(len(got), len(exp_steps))):
                g = got[i] if i < len(got) else None
                e = exp_steps[i] if i < len(exp_steps) else None
                if g != e:
                    print(f"  step {i + 1}: got {json.dumps(g)}")
                    print(f"          exp {json.dumps(e)}")
                    if g and e:
                        for field in g:
                            if g[field] != e[field]:
                                field_mismatches[field] += 1
                    elif g:
                        field_mismatches["extra_step"] += 1
                    else:
                        field_mismatches["missing_step"] += 1
    print(f"\nstatus accuracy: {status_ok}/{len(cases)}")
    print(f"exact-steps match: {exact_ok}/{len(cases)}")
    print(f"field mismatches: {dict(field_mismatches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
