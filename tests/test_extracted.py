"""Tests for the PDF/image extraction reader (RECORD lines).

Covers the parser contract, not the transcriptions themselves: a RECORD
line yields one observation, malformed lines are skipped (never repaired),
and free-text transcription is never parsed. One integration test checks
the checked-in evidence_58 extraction against the real dataset when it is
present next to the repo; it skips cleanly inside code.zip without data.

Run with: python3 -m unittest discover -s tests -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.engine import (  # noqa: E402
    load_dataset,
    parse_extracted_records,
    parse_time,
)

DATASET = Path(__file__).resolve().parents[2] / "orchestrate-dataset" / "dataset"


def write_records(tmp: Path, body: str) -> Path:
    path = tmp / "evidence_99.records"
    path.write_text(body, encoding="utf-8")
    return path


class TestExtractedRecords(unittest.TestCase):
    def test_valid_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_records(
                Path(tmp),
                "# comment\n"
                "RECORD system_id=support_platform; resource_id=support_001; "
                "category=SUPPORT_ATTACHMENT; state=PRESENT; "
                "identifiers=Priya.Raman@Gmail.com|+91 98765 73142\n")
            obs = parse_extracted_records(
                path, "evidence_99", parse_time("2026-09-12T07:30:00Z"))
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].resource_id, "support_001")
        self.assertEqual(obs[0].category, "SUPPORT_ATTACHMENT")
        self.assertEqual(obs[0].state, "PRESENT")
        # Emails are lowercased (engine convention); phones kept verbatim.
        self.assertIn("priya.raman@gmail.com", obs[0].identifiers)
        self.assertIn("+91 98765 73142", obs[0].identifiers)
        self.assertEqual(obs[0].observed_at,
                         parse_time("2026-09-12T07:30:00Z"))

    def test_malformed_lines_skipped_not_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_records(
                Path(tmp),
                "RECORD system_id=nope; resource_id=x_1; "
                "category=USER_PROFILE; state=PRESENT\n"
                "RECORD system_id=account_service; resource_id=account_1; "
                "category=USER_PROFILE; state=WRONG\n"
                "this is free transcription text mentioning account_2\n"
                "RECORD system_id=account_service; resource_id=account_3; "
                "category=USER_PROFILE; state=PRESENT; identifiers=a@b.co\n")
            obs = parse_extracted_records(path, "evidence_99", None)
        # Only the well-formed line survives; narrative text never parses.
        self.assertEqual([o.resource_id for o in obs], ["account_3"])

    def test_retention_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_records(
                Path(tmp),
                "RECORD system_id=security_service; "
                "resource_id=audit_record_003; category=SECURITY_AUDIT_LOG; "
                "state=PRESENT; identifiers=user_03; "
                "retention_until=2027-08-25T04:03:00Z\n")
            obs = parse_extracted_records(path, "evidence_99", None)
        self.assertEqual(obs[0].retention_until,
                         parse_time("2027-08-25T04:03:00Z"))


@unittest.skipUnless(DATASET.exists(), "dataset not present next to repo")
class TestCheckedInExtraction(unittest.TestCase):
    def test_evidence_58_links_support_001(self):
        data = load_dataset(DATASET)
        matches = [o for o in data.observations
                   if o.file_id == "evidence_58"]
        self.assertEqual(len(matches), 1)
        obs = matches[0]
        self.assertEqual((obs.system_id, obs.resource_id),
                         ("support_platform", "support_001"))
        self.assertEqual(obs.category, "SUPPORT_ATTACHMENT")
        self.assertIn("priya.raman@gmail.com", obs.identifiers)


if __name__ == "__main__":
    unittest.main()
