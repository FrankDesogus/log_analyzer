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
            unknown_samples_path = base_path / "unknown_samples.json"

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
                unknown_samples_output_path=unknown_samples_path,
            )

            unknown_events = json.loads(unknown_events_path.read_text(encoding="utf-8"))
            unknown_summary = json.loads(unknown_summary_path.read_text(encoding="utf-8"))
            unknown_samples = json.loads(unknown_samples_path.read_text(encoding="utf-8"))
            parser_report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(len(unknown_events), 2)
            self.assertEqual(
                sorted(unknown_events[0].keys()),
                sorted(parser.UNKNOWN_EVENT_FIELDS),
            )
            self.assertEqual(unknown_summary["total_unknown_events"], 2)
            self.assertEqual(unknown_summary["unique_pattern_count"], 2)
            self.assertGreaterEqual(len(unknown_summary["top_raw_message_patterns"]), 1)
            self.assertGreaterEqual(len(unknown_samples), 1)
            self.assertEqual(parser_report["unknown_events_exported_count"], 2)
            self.assertEqual(parser_report["unknown_event_count_total"], 2)
            self.assertEqual(
                Path(parser_report["generated_files"]["unknown_events"]).name,
                "unknown_events.json",
            )
            self.assertEqual(
                Path(parser_report["generated_files"]["unknown_summary"]).name,
                "unknown_summary.json",
            )
            self.assertEqual(
                Path(parser_report["generated_files"]["unknown_samples"]).name,
                "unknown_samples.json",
            )

    def test_new_patterns_are_not_exported_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp)
            input_path = base_path / "in.log"
            parsed_path = base_path / "parsed_events.json"
            canonical_path = base_path / "canonical_events.json"
            report_path = base_path / "parser_report.json"
            unknown_events_path = base_path / "unknown_events.json"
            unknown_summary_path = base_path / "unknown_summary.json"
            unknown_samples_path = base_path / "unknown_samples.json"

            input_path.write_text(
                "\n".join(
                    [
                        "10.0.0.1 Apr 23 12:00:00 ap01 daemon info kernel: [773256.261912] [STA_TRACKER] DNS request timed out; [STA: ac:f2:3c:00:18:b5][QUERY: teams.microsoft.com.] [DNS_SERVER :10.10.241.10] [TXN_ID a383] [SRCPORT 50607]",
                        "10.0.0.1 Apr 23 12:00:01 ap01 daemon info kernel: [772878.601432] ubnt_get_scan_result: sanity check failed, invalid BssEntry",
                        "10.0.0.1 Apr 23 12:00:02 ap01 daemon info kernel: [773521.070054] sh (25922): drop_caches: 3",
                        "10.0.0.1 Apr 23 12:00:03 ap01 daemon info kernel: [772920.705502] 80211> CFG80211_OpsStaDel ==> for bssid (0E:EA:14:AF:96:A5)",
                        "10.0.0.1 Apr 23 12:00:04 ap01 daemon info kernel: [772920.705607] 80211> CFG80211_OpsStaDel <==",
                        "10.0.0.1 Apr 23 12:00:05 ap01 daemon info kernel: [772918.075520] RTMPCheckEtherType() ==> EAP Packet PortSecure: 2, bClearFrame 1",
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
                unknown_samples_output_path=unknown_samples_path,
            )

            unknown_events = json.loads(unknown_events_path.read_text(encoding="utf-8"))
            unknown_summary = json.loads(unknown_summary_path.read_text(encoding="utf-8"))
            parser_report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(unknown_events, [])
            self.assertEqual(unknown_summary["total_unknown_events"], 0)
            self.assertEqual(json.loads(unknown_samples_path.read_text(encoding="utf-8")), [])
            self.assertEqual(parser_report["unknown_event_count"], 0)
            self.assertEqual(parser_report["unknown_events_exported_count"], 0)
            self.assertIn("event_category_counts", parser_report)


if __name__ == "__main__":
    unittest.main()
