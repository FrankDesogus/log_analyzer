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

    def test_sta_assoc_tracker_dns_timeout_json(self) -> None:
        event = self._parse_message(
            'stahtd[3887]: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"ac:f2:3c:00:18:b5","vap":"rai2","event_type":"dns timeout","assoc_status":"0","query_0":"teams.microsoft.com.","query_server_0":"10.10.241.11","query_1":"www.msftconnecttest.com.","query_server_1":"10.10.241.10"}'
        )
        self.assertEqual(event.event_type, "dns_timeout")
        self.assertEqual(event.event_category, "network_dns")
        self.assertEqual(event.client_mac, "ac:f2:3c:00:18:b5")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.process_name, "stahtd")
        self.assertEqual(event.dns_queries, ["teams.microsoft.com.", "www.msftconnecttest.com."])
        self.assertEqual(event.dns_servers, ["10.10.241.11", "10.10.241.10"])
        self.assertEqual(event.assoc_status, "0")
        self.assertEqual(event.tracker_message_type, "STA_ASSOC_TRACKER")

    def test_reassoc_request(self) -> None:
        event = self._parse_message(
            "[772916.596142] rai2:[recv reassoc_req]. TA:[76:27:03:0e:78:15], RA:[0e:ea:14:a0:22:a7] machdr_seq:2735"
        )
        self.assertEqual(event.event_type, "reassoc_request")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.ap_mac, "0e:ea:14:a0:22:a7")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.internal_event_ts, "772916.596142")

    def test_cfg80211_assoc_req_handler(self) -> None:
        event = self._parse_message("[772916.596181] CFG80211_AssocReqHandler <<<<<<")
        self.assertEqual(event.event_type, "cfg80211_assoc_request_handler")
        self.assertEqual(event.event_category, "wifi_driver")
        self.assertEqual(event.internal_event_ts, "772916.596181")
        self.assertIsNone(event.client_mac)
        self.assertIsNone(event.radio)

    def test_eapol_packet_and_key_events(self) -> None:
        packet = self._parse_message(
            "[772918.075498] rt28xx_send_packets Send EAPOL of length 113 from hostapd"
        )
        self.assertEqual(packet.event_type, "eapol_packet")
        self.assertEqual(packet.event_category, "wifi_eapol")
        self.assertEqual(packet.eapol_direction, "send")
        self.assertEqual(packet.eapol_length, 113)
        self.assertEqual(packet.eapol_source, "hostapd")

        m1 = self._parse_message(
            "[772918.075512] ra1: Send EAPOL-Key M1, DA=76:27:03:0e:78:15, SA=0e:ea:14:90:22:a6, len=113"
        )
        self.assertEqual(m1.event_type, "eapol_key")
        self.assertEqual(m1.eapol_message, "M1")
        self.assertEqual(m1.eapol_direction, "send")
        self.assertEqual(m1.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(m1.ap_mac, "0e:ea:14:90:22:a6")
        self.assertEqual(m1.radio, "ra1")

        m2 = self._parse_message(
            "[772918.097284] ra1: Recv EAPOL-Key M2, DA=0e:ea:14:90:22:a6, SA=76:27:03:0e:78:15, len=129"
        )
        self.assertEqual(m2.eapol_message, "M2")
        self.assertEqual(m2.eapol_direction, "recv")
        self.assertEqual(m2.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(m2.ap_mac, "0e:ea:14:90:22:a6")

    def test_key_add_delete_and_disconnect_driver_patterns(self) -> None:
        key_add = self._parse_message("[772916.623363] 80211> KeyAdd STA(76:27:03:0E:78:15) ==>")
        self.assertEqual(key_add.event_type, "wifi_key_add")
        self.assertEqual(key_add.event_category, "wifi_security")
        self.assertEqual(key_add.client_mac, "76:27:03:0e:78:15")

        key_del = self._parse_message("[772920.709336] 80211> KeyDel STA(76:27:03:0E:78:15) ==>")
        self.assertEqual(key_del.event_type, "wifi_key_delete")
        self.assertEqual(key_del.client_mac, "76:27:03:0e:78:15")

        ap_key_add = self._parse_message("[772916.623368] 80211> AP Key Add")
        self.assertEqual(ap_key_add.event_type, "wifi_ap_key_add")

        sta_del = self._parse_message(
            "[772920.705516] 80211> Delete STA(76:27:03:0E:78:15), reason:0x80000008 ==>"
        )
        self.assertEqual(sta_del.event_type, "station_delete")
        self.assertEqual(sta_del.reason, "0x80000008")

        ap_sta_del = self._parse_message(
            "[772920.705528] rai2: (CFG80211_ApStaDel) STA_DEL (76:27:03:0e:78:15) reason:0x80000008"
        )
        self.assertEqual(ap_sta_del.event_type, "cfg80211_station_delete")
        self.assertEqual(ap_sta_del.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(ap_sta_del.radio, "rai2")

        deauth = self._parse_message(
            "[772920.705545] rai2:[send deauth] TA:[0e:ea:14:af:96:a5], RA:[76:27:03:0e:78:15] machdr_seq=0, reason:8, protection=0"
        )
        self.assertEqual(deauth.event_type, "deauth_sent")
        self.assertEqual(deauth.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(deauth.ap_mac, "0e:ea:14:af:96:a5")
        self.assertEqual(deauth.protection, 0)

        radius_del = self._parse_message(
            "[772920.709487] rai2: (CFG80211_ApStaDel) radius entry[0] DEL (76:27:03:0e:78:15)"
        )
        self.assertEqual(radius_del.event_type, "radius_entry_delete")
        self.assertEqual(radius_del.client_mac, "76:27:03:0e:78:15")

    def test_driver_missing_station_entry(self) -> None:
        event = self._parse_message("[772920.709391] Can't find pEntry in CFG80211_StaPortSecured")
        self.assertEqual(event.event_type, "driver_missing_station_entry")
        self.assertEqual(event.event_category, "wifi_driver")
        self.assertEqual(event.driver_context, "CFG80211_StaPortSecured")


if __name__ == "__main__":
    unittest.main()
