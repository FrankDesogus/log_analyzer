import json
import tempfile
import unittest
from pathlib import Path

from detection.enrichment import enrich_canonical_event, run_detection_layer


class DetectionLayerTests(unittest.TestCase):
    def test_enrich_wifi_auth_disconnect_sequence(self) -> None:
        event = {
            "canonical_event_id": "c1",
            "canonical_event_type": "wifi_auth_disconnect_sequence",
            "raw_event_count": 9,
            "sequence_summary": {
                "disconnect_count": 3,
                "rssi_avg": -88,
            },
            "event_types_seen": ["auth_request", "disconnect"],
        }

        enriched = enrich_canonical_event(event)

        self.assertGreaterEqual(enriched["severity_score"], 60)
        self.assertTrue(enriched["incident_candidate"])
        self.assertIn("repeated_disconnect", enriched["detection_tags"])

    def test_run_detection_layer_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                run_detection_layer(
                    canonical_input_path=base / "missing.json",
                    enriched_output_path=base / "enriched.json",
                    summary_output_path=base / "summary.json",
                )

    def test_run_detection_layer_outputs_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            canonical_path = base / "canonical_events.json"
            enriched_path = base / "enriched_canonical_events.json"
            summary_path = base / "detection_summary.json"

            canonical_payload = {
                "canonical_events": [
                    {
                        "canonical_event_id": "c2",
                        "canonical_event_type": "wifi_disconnect_sequence",
                        "raw_event_count": 10,
                        "duration_ms": 1200,
                        "raw_line_numbers": [10, 11, 12, 13, 14],
                        "sequence_summary": {"disconnect_count": 4},
                        "event_types_seen": ["disconnect"],
                    }
                ]
            }
            canonical_path.write_text(json.dumps(canonical_payload), encoding="utf-8")

            summary = run_detection_layer(canonical_path, enriched_path, summary_path)

            self.assertEqual(summary["total_enriched_events"], 1)
            self.assertTrue(enriched_path.exists())
            self.assertTrue(summary_path.exists())


if __name__ == "__main__":
    unittest.main()
