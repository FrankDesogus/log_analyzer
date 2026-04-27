import unittest

from src.correlation import build_canonical_events


class CanonicalCorrelationTests(unittest.TestCase):
    def test_internal_ts_sequence_is_correlated(self) -> None:
        events = [
            {
                "line_number": 10,
                "source_ip": "10.0.0.10",
                "host": "ap01",
                "client_mac": "c4:82:e1:81:04:f9",
                "ap_mac": "0e:ea:14:90:37:c6",
                "radio": "ra1",
                "normalized_timestamp": "2026-04-23T12:00:00",
                "process_name": "kernel",
                "process": "kernel",
                "event_type": "auth_request",
                "event_category": "wifi_auth",
                "rssi": -55,
                "internal_event_ts_float": 773313.921726,
            },
            {
                "line_number": 11,
                "source_ip": "10.0.0.10",
                "host": "ap01",
                "client_mac": "c4:82:e1:81:04:f9",
                "ap_mac": "0e:ea:14:90:37:c6",
                "radio": "ra1",
                "normalized_timestamp": "2026-04-23T12:00:00",
                "process_name": "wevent",
                "process": "wevent",
                "event_type": "auth_response",
                "event_category": "wifi_auth",
                "rssi": -58,
                "internal_event_ts_float": 773313.930,
            },
            {
                "line_number": 12,
                "source_ip": "10.0.0.10",
                "host": "ap01",
                "client_mac": "c4:82:e1:81:04:f9",
                "ap_mac": "0e:ea:14:90:37:c6",
                "radio": "ra1",
                "normalized_timestamp": "2026-04-23T12:00:00",
                "process_name": "hostapd",
                "process": "hostapd",
                "event_type": "disconnect",
                "event_category": "wifi_disconnect",
                "rssi": -62,
                "internal_event_ts_float": 773313.935,
            },
        ]

        payload = build_canonical_events(events)

        self.assertEqual(len(payload["raw_events"]), 3)
        self.assertEqual(len(payload["canonical_events"]), 1)

        canonical = payload["canonical_events"][0]
        self.assertEqual(canonical["raw_event_count"], 3)
        self.assertEqual(canonical["raw_line_numbers"], [10, 11, 12])
        self.assertEqual(canonical["canonical_event_type"], "wifi_auth_disconnect_sequence")
        self.assertEqual(
            canonical["event_types_seen"], ["auth_request", "auth_response", "disconnect"]
        )
        self.assertEqual(
            canonical["correlation_strategy"],
            "source_ip+client_mac+radio_or_fallback+internal_event_ts_window",
        )
        self.assertEqual(canonical["sequence_summary"]["rssi_min"], -62)
        self.assertEqual(canonical["sequence_summary"]["rssi_max"], -55)

    def test_different_radio_does_not_correlate(self) -> None:
        events = [
            {
                "line_number": 20,
                "source_ip": "10.0.0.20",
                "host": "ap02",
                "client_mac": "aa:bb:cc:dd:ee:ff",
                "radio": "ra0",
                "normalized_timestamp": "2026-04-23T12:10:00",
                "event_type": "auth_request",
                "event_category": "wifi_auth",
                "process_name": "kernel",
                "process": "kernel",
                "internal_event_ts_float": 990.1,
            },
            {
                "line_number": 21,
                "source_ip": "10.0.0.20",
                "host": "ap02",
                "client_mac": "aa:bb:cc:dd:ee:ff",
                "radio": "ra1",
                "normalized_timestamp": "2026-04-23T12:10:00",
                "event_type": "auth_response",
                "event_category": "wifi_auth",
                "process_name": "hostapd",
                "process": "hostapd",
                "internal_event_ts_float": 990.2,
            },
        ]

        payload = build_canonical_events(events)
        self.assertEqual(len(payload["canonical_events"]), 2)

    def test_gap_over_threshold_creates_new_canonical_event(self) -> None:
        events = [
            {
                "line_number": 30,
                "source_ip": "10.0.0.30",
                "client_mac": "11:22:33:44:55:66",
                "radio": "ra1",
                "event_type": "auth_request",
                "internal_event_ts_float": 100.000,
            },
            {
                "line_number": 31,
                "source_ip": "10.0.0.30",
                "client_mac": "11:22:33:44:55:66",
                "radio": "ra1",
                "event_type": "auth_response",
                "internal_event_ts_float": 100.040,
            },
        ]

        payload = build_canonical_events(events, max_gap_ms=15)
        self.assertEqual(len(payload["canonical_events"]), 2)

    def test_eapol_keys_generate_handshake_canonical_type(self) -> None:
        events = [
            {
                "line_number": 40,
                "source_ip": "10.0.0.40",
                "client_mac": "76:27:03:0e:78:15",
                "ap_mac": "0e:ea:14:90:22:a6",
                "radio": "ra1",
                "event_type": "eapol_key",
                "event_category": "wifi_eapol",
                "internal_event_ts_float": 1000.001,
            },
            {
                "line_number": 41,
                "source_ip": "10.0.0.40",
                "client_mac": "76:27:03:0e:78:15",
                "ap_mac": "0e:ea:14:90:22:a6",
                "radio": "ra1",
                "event_type": "eapol_key",
                "event_category": "wifi_eapol",
                "internal_event_ts_float": 1000.010,
            },
        ]
        payload = build_canonical_events(events, max_gap_ms=20)
        self.assertEqual(len(payload["canonical_events"]), 1)
        self.assertEqual(
            payload["canonical_events"][0]["canonical_event_type"],
            "wifi_eapol_handshake_sequence",
        )

    def test_new_event_families_map_to_expected_canonical_types(self) -> None:
        payload = build_canonical_events(
            [
                {
                    "line_number": 50,
                    "source_ip": "10.0.0.50",
                    "client_mac": "76:27:03:0e:78:15",
                    "ap_mac": "0e:ea:14:a0:22:a7",
                    "event_type": "fast_transition_roam",
                    "event_category": "wifi_roam",
                    "internal_event_ts_float": 2000.001,
                },
                {
                    "line_number": 51,
                    "source_ip": "10.0.0.51",
                    "client_mac": "c4:82:e1:71:52:e0",
                    "radio": "ra0",
                    "event_type": "assoc_tracker_failure",
                    "event_category": "wifi_association",
                    "internal_event_ts_float": 3000.001,
                },
                {
                    "line_number": 52,
                    "source_ip": "10.0.0.52",
                    "client_mac": "ac:f2:3c:00:18:b5",
                    "radio": "rai0",
                    "event_type": "dns_timeout",
                    "event_category": "network_dns",
                    "internal_event_ts_float": 4000.001,
                },
                {
                    "line_number": 53,
                    "source_ip": "10.0.0.53",
                    "event_type": "device_config_report",
                    "event_category": "device_management",
                    "process_name": "mcad",
                    "internal_event_ts_float": 5000.001,
                },
            ]
        )
        canonical_types = {event["canonical_event_type"] for event in payload["canonical_events"]}
        self.assertIn("wifi_roam_sequence", canonical_types)
        self.assertIn("wifi_assoc_failure_sequence", canonical_types)
        self.assertIn("network_dns_anomaly_sequence", canonical_types)
        self.assertIn("device_management_sequence", canonical_types)

    def test_known_disconnect_related_events_are_not_unknown(self) -> None:
        payload = build_canonical_events(
            [
                {
                    "line_number": 60,
                    "source_ip": "10.0.0.60",
                    "client_mac": "76:27:03:0e:78:15",
                    "radio": "rai2",
                    "event_type": "cfg80211_station_delete_start",
                    "event_category": "wifi_driver",
                    "internal_event_ts_float": 6000.001,
                },
                {
                    "line_number": 61,
                    "source_ip": "10.0.0.60",
                    "client_mac": "76:27:03:0e:78:15",
                    "radio": "rai2",
                    "event_type": "station_table_delete",
                    "event_category": "wifi_driver",
                    "internal_event_ts_float": 6000.010,
                },
                {
                    "line_number": 62,
                    "source_ip": "10.0.0.60",
                    "client_mac": "76:27:03:0e:78:15",
                    "radio": "rai2",
                    "event_type": "driver_missing_station_entry",
                    "event_category": "wifi_driver",
                    "internal_event_ts_float": 6000.012,
                },
            ]
        )
        self.assertEqual(len(payload["canonical_events"]), 1)
        self.assertEqual(
            payload["canonical_events"][0]["canonical_event_type"],
            "wifi_disconnect_sequence",
        )

    def test_unknown_sequence_requires_only_unknown_event_types(self) -> None:
        payload = build_canonical_events(
            [
                {
                    "line_number": 70,
                    "source_ip": "10.0.0.70",
                    "event_type": "unknown",
                    "event_category": "unknown",
                    "process_name": "unknown",
                    "internal_event_ts_float": 7000.001,
                }
            ]
        )
        self.assertEqual(
            payload["canonical_events"][0]["canonical_event_type"],
            "wifi_unknown_sequence",
        )

    def test_device_management_processes_map_to_device_management_sequence(self) -> None:
        payload = build_canonical_events(
            [
                {
                    "line_number": 80,
                    "source_ip": "10.0.0.80",
                    "event_type": "controller_config",
                    "event_category": "controller_config",
                    "process_name": "syswrapper",
                    "internal_event_ts_float": 8000.001,
                }
            ]
        )
        self.assertEqual(
            payload["canonical_events"][0]["canonical_event_type"],
            "device_management_sequence",
        )

    def test_wifi_key_events_map_to_wifi_security_sequence(self) -> None:
        payload = build_canonical_events(
            [
                {
                    "line_number": 90,
                    "source_ip": "10.0.0.90",
                    "client_mac": "de:ad:be:ef:00:90",
                    "radio": "ra1",
                    "event_type": "wifi_key_add",
                    "event_category": "wifi_security",
                    "internal_event_ts_float": 9000.001,
                },
                {
                    "line_number": 91,
                    "source_ip": "10.0.0.90",
                    "client_mac": "de:ad:be:ef:00:90",
                    "radio": "ra1",
                    "event_type": "wifi_ap_key_add",
                    "event_category": "wifi_security",
                    "internal_event_ts_float": 9000.005,
                },
            ]
        )
        self.assertEqual(len(payload["canonical_events"]), 1)
        canonical = payload["canonical_events"][0]
        self.assertEqual(canonical["canonical_event_type"], "wifi_security_sequence")
        self.assertEqual(canonical["sequence_summary"]["wifi_key_add_count"], 1)
        self.assertEqual(canonical["sequence_summary"]["wifi_ap_key_add_count"], 1)


if __name__ == "__main__":
    unittest.main()
