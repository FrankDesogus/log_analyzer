import json
import tempfile
import unittest
from pathlib import Path

from src import parser


class UnknownOutputsTests(unittest.TestCase):
    def test_unknown_outputs_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp)
            input_path = base_path / "in.log"
            parsed_path = base_path / "parsed_events.json"
            canonical_path = base_path / "canonical_events.json"
            report_path = base_path / "parser_report.json"
            unknown_events_path = base_path / "unknown_events.json"
            unknown_summary_path = base_path / "unknown_summary.json"

            input_path.write_text(
                "\n".join(
                    [
                        (
                            "10.0.0.1 Apr 23 12:00:00 ap01 daemon info kernel: "
                            "[773313.921726] mystery from aa:bb:cc:dd:ee:ff to 192.168.1.2 id 123456"
                        ),
                        (
                            "10.0.0.2 Apr 23 12:00:01 ap02 daemon notice dnsmasq: "
                            "started version 12345 cachesize 150"
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parser.parse_file(
                input_path,
                parsed_path,
                canonical_output_path=canonical_path,
                parser_report_output_path=report_path,
                unknown_events_output_path=unknown_events_path,
                unknown_summary_output_path=unknown_summary_path,
            )

            unknown_events = json.loads(unknown_events_path.read_text(encoding="utf-8"))
            unknown_summary = json.loads(unknown_summary_path.read_text(encoding="utf-8"))
            parser_report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(len(unknown_events), 1)
            self.assertEqual(
                sorted(unknown_events[0].keys()),
                sorted(parser.UNKNOWN_EVENT_FIELDS),
            )
            self.assertEqual(unknown_summary["total_unknown_events"], 1)
            self.assertGreaterEqual(len(unknown_summary["top_raw_message_patterns"]), 1)
            self.assertLessEqual(len(unknown_summary["sample_unknown_events"]), 50)
            self.assertEqual(parser_report["unknown_events_exported_count"], 1)
            self.assertEqual(
                Path(parser_report["generated_files"]["unknown_events"]).name,
                "unknown_events.json",
            )
            self.assertEqual(
                Path(parser_report["generated_files"]["unknown_summary"]).name,
                "unknown_summary.json",
            )


if __name__ == "__main__":
    unittest.main()
