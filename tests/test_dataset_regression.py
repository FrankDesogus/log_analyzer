import json
import tempfile
import unittest
from pathlib import Path

from src import parser


class DatasetRegressionTests(unittest.TestCase):
    def test_dataset_counts_and_unknown_reduction(self) -> None:
        input_path = Path("data/raw/syslog")
        if not input_path.exists():
            self.skipTest("dataset file data/raw/syslog not available in this environment")

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parsed_path = base / "parsed_events.json"
            canonical_path = base / "canonical_events.json"
            report_path = base / "parser_report.json"
            unknown_events_path = base / "unknown_events.json"
            unknown_summary_path = base / "unknown_summary.json"

            parser.parse_file(
                input_path,
                parsed_path,
                canonical_output_path=canonical_path,
                parser_report_output_path=report_path,
                unknown_events_output_path=unknown_events_path,
                unknown_summary_output_path=unknown_summary_path,
            )

            report = json.loads(report_path.read_text(encoding="utf-8"))
            canonical = json.loads(canonical_path.read_text(encoding="utf-8"))

            self.assertEqual(report["total_raw_events"], 15985)
            self.assertEqual(report["unknown_events_exported_count"], report["unknown_event_count_total"])
            self.assertLess(report["unknown_event_count_total"], 1103)
            self.assertNotIn("raw_events", canonical)
            self.assertIn("canonical_events", canonical)


if __name__ == "__main__":
    unittest.main()
