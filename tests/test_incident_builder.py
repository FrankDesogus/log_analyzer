import json
import tempfile
import unittest
from pathlib import Path

from detection.incident_builder import build_incidents, run_incident_builder


class IncidentBuilderTests(unittest.TestCase):
    def test_groups_wifi_instability_by_client_and_time_window(self) -> None:
        enriched_events = [
            {
                "canonical_event_id": "c1",
                "canonical_event_type": "wifi_auth_disconnect_sequence",
                "incident_type": "wifi_instability",
                "severity_score": 62,
                "severity_level": "medium",
                "confidence_score": 0.7,
                "incident_candidate": True,
                "client_mac": "aa:bb:cc:dd:ee:ff",
                "source_ip": "10.0.0.10",
                "radio": "rai0",
                "ap_mac": "11:22:33:44:55:66",
                "first_internal_event_ts": 100.0,
                "last_internal_event_ts": 102.0,
                "normalized_timestamp": "2026-04-28T10:00:00",
                "detection_tags": ["incident_candidate"],
                "detection_reason": ["first reason"],
            },
            {
                "canonical_event_id": "c2",
                "canonical_event_type": "wifi_disconnect_sequence",
                "incident_type": "wifi_instability",
                "severity_score": 58,
                "severity_level": "medium",
                "confidence_score": 0.65,
                "incident_candidate": False,
                "client_mac": "aa:bb:cc:dd:ee:ff",
                "source_ip": "10.0.0.15",
                "radio": "rai0",
                "ap_mac": "11:22:33:44:55:66",
                "first_internal_event_ts": 140.0,
                "last_internal_event_ts": 141.0,
                "normalized_timestamp": "2026-04-28T10:00:40",
                "detection_tags": ["wifi_disconnect"],
                "detection_reason": ["second reason"],
            },
            {
                "canonical_event_id": "c3",
                "canonical_event_type": "wifi_disconnect_sequence",
                "incident_type": "wifi_instability",
                "severity_score": 56,
                "severity_level": "medium",
                "confidence_score": 0.6,
                "incident_candidate": False,
                "client_mac": "aa:bb:cc:dd:ee:ff",
                "source_ip": "10.0.0.20",
                "radio": "rai1",
                "ap_mac": "11:22:33:44:55:66",
                "first_internal_event_ts": 240.0,
                "last_internal_event_ts": 241.0,
                "normalized_timestamp": "2026-04-28T10:02:20",
                "detection_tags": ["wifi_disconnect"],
                "detection_reason": ["third reason"],
            },
        ]

        incidents = build_incidents(enriched_events, window_seconds=60.0)
        self.assertEqual(len(incidents), 2)
        first = max(incidents, key=lambda item: item["canonical_event_count"])
        self.assertEqual(first["canonical_event_count"], 2)
        self.assertEqual(first["incident_type"], "wifi_instability")

    def test_wifi_noise_not_critical_and_client_flapping_mapped(self) -> None:
        enriched_events = [
            {
                "canonical_event_id": "c4",
                "canonical_event_type": "wifi_disconnect_sequence",
                "incident_type": "wifi_noise",
                "severity_score": 90,
                "confidence_score": 0.9,
                "client_mac": "11:11:11:11:11:11",
                "source_ip": "10.1.1.1",
                "first_internal_event_ts": 10.0,
                "last_internal_event_ts": 11.0,
                "normalized_timestamp": "2026-04-28T10:00:00",
                "detection_tags": ["disconnect_only_sequence"],
                "disconnect_diagnostic_label": "probable_unifi_duplicate_noise",
                "detection_reason": ["noise"],
            },
            {
                "canonical_event_id": "c5",
                "canonical_event_type": "wifi_disconnect_sequence",
                "incident_type": "wifi_instability",
                "severity_score": 61,
                "confidence_score": 0.72,
                "client_mac": "22:22:22:22:22:22",
                "source_ip": "10.1.1.2",
                "first_internal_event_ts": 20.0,
                "last_internal_event_ts": 21.0,
                "normalized_timestamp": "2026-04-28T10:00:10",
                "detection_tags": ["client_flapping"],
                "disconnect_diagnostic_label": "client_flapping",
                "detection_reason": ["flapping"],
            },
        ]

        incidents = build_incidents(enriched_events, window_seconds=60.0)
        by_type = {item["incident_type"]: item for item in incidents}
        self.assertIn("wifi_noise", by_type)
        self.assertIn("client_flapping", by_type)
        self.assertLess(by_type["wifi_noise"]["severity_score"], 85)

    def test_run_incident_builder_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            enriched_path = base / "enriched.json"
            incidents_path = base / "incidents.json"
            summary_path = base / "incident_summary.json"

            payload = {
                "canonical_events": [
                    {
                        "canonical_event_id": "c6",
                        "canonical_event_type": "wifi_security_sequence",
                        "incident_type": "wifi_security",
                        "severity_score": 80,
                        "confidence_score": 0.8,
                        "client_mac": "33:33:33:33:33:33",
                        "source_ip": "10.2.2.2",
                        "first_internal_event_ts": 50.0,
                        "last_internal_event_ts": 55.0,
                        "normalized_timestamp": "2026-04-28T10:05:00",
                        "detection_tags": ["wifi_security"],
                        "detection_reason": ["security signal"],
                    }
                ]
            }
            enriched_path.write_text(json.dumps(payload), encoding="utf-8")

            summary = run_incident_builder(enriched_path, incidents_path, summary_path)
            self.assertEqual(summary["total_incidents"], 1)
            self.assertTrue(incidents_path.exists())
            self.assertTrue(summary_path.exists())


if __name__ == "__main__":
    unittest.main()
