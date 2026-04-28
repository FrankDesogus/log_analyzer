import json
import tempfile
import unittest
from pathlib import Path

from src import parser


class UnknownOutputsTests(unittest.TestCase):
    def test_quality_report_includes_canonical_gap_metrics(self) -> None:
        parsed_events = [
            {"normalized_timestamp": "2026-04-23T12:00:00", "parse_status": "parsed", "event_type": "unknown", "event_category": "unknown"},
            {"normalized_timestamp": "2026-04-23T12:00:08", "parse_status": "parsed", "event_type": "unknown", "event_category": "unknown"},
        ]
        canonical_events = [
            {
                "canonical_event_id": "canon-1",
                "canonical_event_type": "wifi_unknown_sequence",
                "raw_event_count": 2,
                "raw_line_numbers": [10, 900],
                "raw_event_indexes": [0, 1],
                "event_types_seen": ["unknown"],
            }
        ]
        unknown_events = [{"event_type": None, "event_category": "unknown"}]
        unknown_summary = {"total_unknown_events": 1, "unique_pattern_count": 1, "top_patterns": []}

        report = parser.build_quality_report(
            parsed_events=parsed_events,
            canonical_events=canonical_events,
            unknown_events=unknown_events,
            unknown_summary=unknown_summary,
            parser_report={"unknown_event_count": 1},
        )

        self.assertEqual(report["canonical_sequences_with_large_line_gap"], 1)
        self.assertEqual(report["canonical_sequences_with_large_timestamp_gap"], 1)
        self.assertEqual(report["max_raw_line_gap_in_canonical_sequence"], 890)
        self.assertEqual(report["max_timestamp_gap_seconds_in_canonical_sequence"], 8.0)
        self.assertEqual(report["max_consecutive_line_gap"], 890)
        self.assertEqual(report["max_consecutive_timestamp_gap_seconds"], 8.0)
        self.assertIn("wifi_unknown_sequence", report["suspicious_sequences_by_type"])
        self.assertGreaterEqual(len(report["suspicious_canonical_sequences_sample"]), 1)
        self.assertIn("disconnect_sequence_quality", report)
        self.assertEqual(report["disconnect_sequence_quality"]["total_wifi_disconnect_sequences"], 0)

    def test_unknown_outputs_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp)
            input_path = base_path / "in.log"
            parsed_path = base_path / "parsed_events.json"
            canonical_path = base_path / "canonical_events.json"
            report_path = base_path / "parser_report.json"
            quality_report_path = base_path / "quality_report.json"
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
                quality_report_output_path=quality_report_path,
                unknown_events_output_path=unknown_events_path,
                unknown_summary_output_path=unknown_summary_path,
                unknown_samples_output_path=unknown_samples_path,
            )

            unknown_events = json.loads(unknown_events_path.read_text(encoding="utf-8"))
            unknown_summary = json.loads(unknown_summary_path.read_text(encoding="utf-8"))
            unknown_samples = json.loads(unknown_samples_path.read_text(encoding="utf-8"))
            parser_report = json.loads(report_path.read_text(encoding="utf-8"))
            quality_report = json.loads(quality_report_path.read_text(encoding="utf-8"))

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
            self.assertTrue(quality_report["unknown_files_are_consistent"])
            self.assertEqual(quality_report["unknown_events_exported"], 2)
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
            quality_report_path = base_path / "quality_report.json"
            unknown_events_path = base_path / "unknown_events.json"
            unknown_summary_path = base_path / "unknown_summary.json"
            unknown_samples_path = base_path / "unknown_samples.json"

            input_path.write_text(
                "\n".join(
                    [
                        "10.0.0.1 Apr 23 12:00:00 ap01 daemon info hostapd: WPA: Receive FT: 0e:ea:14:a0:22:a7 STA Roamed: 76:27:03:0e:78:15",
                        '10.0.0.1 Apr 23 12:00:01 ap01 daemon info kernel: stahtd[3888]: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"c4:82:e1:71:52:e0","vap":"ra0","event_type":"failure","assoc_status":"0","auth_failures":"18","event_id":"167","auth_ts":"772859.997409"}',
                        "10.0.0.1 Apr 23 12:00:02 ap01 daemon info kernel: mcad[3901]: wireless_agg_stats.log_sta_anomalies(): bssid=0e:ea:14:af:a1:59 radio=rai0 vap=rai2 sta=ac:f2:3c:00:18:b5 satisfaction_now=60 anomalies=dns_timeout",
                        "10.0.0.1 Apr 23 12:00:03 ap01 daemon info kernel: mcad[3903]: ace_reporter.reporter_save_config(): is_default: false",
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
                quality_report_output_path=quality_report_path,
                unknown_events_output_path=unknown_events_path,
                unknown_summary_output_path=unknown_summary_path,
                unknown_samples_output_path=unknown_samples_path,
            )

            unknown_events = json.loads(unknown_events_path.read_text(encoding="utf-8"))
            unknown_summary = json.loads(unknown_summary_path.read_text(encoding="utf-8"))
            parser_report = json.loads(report_path.read_text(encoding="utf-8"))
            quality_report = json.loads(quality_report_path.read_text(encoding="utf-8"))

            self.assertEqual(unknown_events, [])
            self.assertEqual(unknown_summary["total_unknown_events"], 0)
            self.assertEqual(json.loads(unknown_samples_path.read_text(encoding="utf-8")), [])
            self.assertEqual(parser_report["unknown_event_count"], 0)
            self.assertEqual(parser_report["unknown_events_exported_count"], 0)
            self.assertEqual(quality_report["unknown_events_exported"], 0)
            self.assertIn("event_category_counts", parser_report)

    def test_known_driver_event_with_unknown_category_is_not_exported_as_unknown(self) -> None:
        parsed_events = [
            {
                "line_number": 1,
                "event_type": "driver_queue_flush",
                "event_category": "unknown",
                "raw_message": "cb2, flush one!",
                "parse_status": "parsed",
            },
            {
                "line_number": 2,
                "event_type": None,
                "event_category": "unknown",
                "raw_message": "some unmatched message",
                "parse_status": "parsed",
            },
        ]

        unknown_events = parser.extract_unknown_events(parsed_events)
        self.assertEqual(len(unknown_events), 1)
        self.assertIsNone(unknown_events[0]["event_type"])


if __name__ == "__main__":
    unittest.main()
