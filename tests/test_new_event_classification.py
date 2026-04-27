import unittest

from src.parser import parse_line


class NewEventClassificationTests(unittest.TestCase):
    def _parse_message(self, message: str):
        line = f"10.0.0.1 Apr 23 12:00:00 ap01 daemon info kernel: {message}"
        event = parse_line(line)
        self.assertIsNotNone(event)
        return event

    def test_dns_timeout(self) -> None:
        event = self._parse_message(
            "[773256.261912] [STA_TRACKER] DNS request timed out; "
            "[STA: ac:f2:3c:00:18:b5][QUERY: teams.microsoft.com.] "
            "[DNS_SERVER :10.10.241.10] [TXN_ID a383] [SRCPORT 50607]"
        )
        self.assertEqual(event.event_type, "dns_timeout")
        self.assertEqual(event.event_category, "network_dns")
        self.assertEqual(event.client_mac, "ac:f2:3c:00:18:b5")
        self.assertEqual(event.query, "teams.microsoft.com.")
        self.assertEqual(event.dns_server, "10.10.241.10")
        self.assertEqual(event.transaction_id, "a383")
        self.assertEqual(event.source_port, 50607)
        self.assertEqual(event.internal_event_ts, "773256.261912")

    def test_wifi_scan_error(self) -> None:
        event = self._parse_message(
            "[772878.601432] ubnt_get_scan_result: sanity check failed, invalid BssEntry"
        )
        self.assertEqual(event.event_type, "wifi_scan_error")
        self.assertEqual(event.event_category, "wifi_system")
        self.assertEqual(event.error_type, "invalid_bss_entry")

    def test_drop_caches(self) -> None:
        event = self._parse_message("[773521.070054] sh (25922): drop_caches: 3")
        self.assertEqual(event.event_type, "system_cache_drop")
        self.assertEqual(event.event_category, "system_maintenance")
        self.assertEqual(event.process_name, "sh")
        self.assertEqual(event.drop_caches_value, 3)

    def test_cfg80211_station_delete_start(self) -> None:
        event = self._parse_message(
            "[772920.705502] 80211> CFG80211_OpsStaDel ==> for bssid (0E:EA:14:AF:96:A5)"
        )
        self.assertEqual(event.event_type, "cfg80211_station_delete_start")
        self.assertEqual(event.event_category, "wifi_driver")
        self.assertEqual(event.bssid, "0e:ea:14:af:96:a5")

    def test_cfg80211_station_delete_end(self) -> None:
        event = self._parse_message("[772920.705607] 80211> CFG80211_OpsStaDel <==")
        self.assertEqual(event.event_type, "cfg80211_station_delete_end")
        self.assertEqual(event.event_category, "wifi_driver")

    def test_eap_packet(self) -> None:
        event = self._parse_message(
            "[772918.075520] RTMPCheckEtherType() ==> EAP Packet PortSecure: 2, bClearFrame 1"
        )
        self.assertEqual(event.event_type, "eap_packet")
        self.assertEqual(event.event_category, "wifi_auth")
        self.assertEqual(event.port_secure, 2)
        self.assertEqual(event.clear_frame, 1)

    def test_existing_auth_disconnect_patterns_still_classified(self) -> None:
        auth_req = self._parse_message(
            "[773313.921726] [WIFI] [recv auth_req] TA:[c4:82:e1:81:04:f9] RA:[0e:ea:14:90:37:c6]"
        )
        auth_rsp = self._parse_message(
            "[773313.930001] [WIFI] [send auth_rsp] TA:[0e:ea:14:90:37:c6] RA:[c4:82:e1:81:04:f9]"
        )
        disconnect_evt = self._parse_message(
            "hostapd: STA c4:82:e1:81:04:f9 IEEE 802.11: disassociated"
        )

        self.assertEqual(auth_req.event_type, "auth_request")
        self.assertEqual(auth_rsp.event_type, "auth_response")
        self.assertEqual(disconnect_evt.event_type, "disconnect")


if __name__ == "__main__":
    unittest.main()
