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
            "source_ip+client_mac+radio+internal_event_ts_window",
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


if __name__ == "__main__":
    unittest.main()
