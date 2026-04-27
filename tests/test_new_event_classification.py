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

    def test_station_join_and_assoc_patterns(self) -> None:
        station_join = self._parse_message(
            "[772916.596142] wevent: STA_JOIN ra2:19 [76:27:03:0e:78:15]"
        )
        self.assertEqual(station_join.event_type, "station_join")
        self.assertEqual(station_join.event_category, "wifi_association")
        self.assertEqual(station_join.radio, "ra2")
        self.assertEqual(station_join.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(station_join.aid, 19)

        reassoc_rsp = self._parse_message(
            "[772916.596242] ra2:[send reassoc_rsp]. TA:[0e:ea:14:a0:22:a7], RA:[76:27:03:0e:78:15] status:0 aid:19"
        )
        self.assertEqual(reassoc_rsp.event_type, "reassoc_response")
        self.assertEqual(reassoc_rsp.event_category, "wifi_roam")
        self.assertEqual(reassoc_rsp.ap_mac, "0e:ea:14:a0:22:a7")
        self.assertEqual(reassoc_rsp.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(reassoc_rsp.aid, 19)

        assoc_success = self._parse_message(
            "[772916.596342] [assoc_report] ra2:[76:27:03:0e:78:15] Success:0 aid:19 wcid:4 phy:ax bw:80 mcs:7 wmm:1 rrm:1"
        )
        self.assertEqual(assoc_success.event_type, "assoc_success")
        self.assertEqual(assoc_success.wcid, 4)
        self.assertEqual(assoc_success.bandwidth, "80")

    def test_driver_and_keepalive_patterns(self) -> None:
        insert_evt = self._parse_message("[772916.700001] MacTableInsertEntry(): wcid 4 EntryType:0")
        self.assertEqual(insert_evt.event_type, "station_table_insert")
        self.assertEqual(insert_evt.wcid, 4)
        self.assertEqual(insert_evt.entry_type, 0)

        delete_evt = self._parse_message("[772916.700101] MacTableDeleteEntryWithFlags(): wcid 4")
        self.assertEqual(delete_evt.event_type, "station_table_delete")

        qos_evt = self._parse_message("[772916.700201] entry wcid 4 QosMapSupport=1")
        self.assertEqual(qos_evt.event_type, "station_qos_map_support")
        self.assertEqual(qos_evt.qos_map_support, 1)

        idle_evt = self._parse_message(
            "[772916.700301] ra2: Send NULL to STA-MAC 76:27:03:0e:78:15 idle(300) timeout(5)"
        )
        self.assertEqual(idle_evt.event_type, "station_idle_probe")
        self.assertEqual(idle_evt.idle_seconds, 300)
        self.assertEqual(idle_evt.timeout_seconds, 5)

    def test_fast_transition_roam(self) -> None:
        event = self._parse_message(
            "WPA: Receive FT: 0e:ea:14:a0:22:a7 STA Roamed: 76:27:03:0e:78:15"
        )
        self.assertEqual(event.event_type, "fast_transition_roam")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.ap_mac, "0e:ea:14:a0:22:a7")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.mac, "76:27:03:0e:78:15")

    def test_fast_transition_roam_send(self) -> None:
        event = self._parse_message(
            "WPA: Send FT: RRB UBNT ROAM: STA=76:27:03:0e:78:15 CurrentAP=0e:ea:14:a0:22:a7"
        )
        self.assertEqual(event.event_type, "fast_transition_roam_send")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.ap_mac, "0e:ea:14:a0:22:a7")

    def test_device_config_version_change(self) -> None:
        event = self._parse_message(
            "mcad[3901]: ace_reporter.reporter_handle_response_json(): cfgversion: 1735842944 -> 1735842950"
        )
        self.assertEqual(event.event_type, "device_config_version_change")
        self.assertEqual(event.event_category, "device_config")
        self.assertEqual(event.old_config_version, "1735842944")
        self.assertEqual(event.new_config_version, "1735842950")

    def test_unifi_settings_audit_cef_extensions(self) -> None:
        event = self._parse_message(
            "true UNIFIaccessMethod=web UNIFIsettingsSection=System UNIFIsettingsEntry=rsyslogd "
            "UNIFIadmin=UniFi User msg=UniFi User made a change to in System settings"
        )
        self.assertEqual(event.event_type, "unifi_config_audit")
        self.assertEqual(event.event_category, "device_config")

    def test_system_state_lock_warning(self) -> None:
        failed_lock = self._parse_message("[WARN ] Failed to lock /var/run/system.state.lock")
        skip_reload = self._parse_message("[state is locked] skipping reload")

        self.assertEqual(failed_lock.event_type, "system_state_lock_warning")
        self.assertEqual(failed_lock.event_category, "system_maintenance")
        self.assertEqual(skip_reload.event_type, "system_state_lock_warning")
        self.assertEqual(skip_reload.event_category, "system_maintenance")

    def test_unifi_cef_config_modified(self) -> None:
        event = self._parse_message(
            'CEF:0|Ubiquiti|UniFi Network|8.0.7|100|Config Modified|5|cs2=web cs3=services cs4=advanced_features suser=admin start=1713620478 src=10.0.0.9 site=default host=udm'
        )
        self.assertEqual(event.event_type, "unifi_config_audit")
        self.assertEqual(event.event_category, "device_config")
        self.assertEqual(event.unifi_access_method, "web")
        self.assertEqual(event.unifi_settings_section, "services")
        self.assertEqual(event.unifi_settings_entry, "advanced_features")
        self.assertEqual(event.unifi_admin, "admin")
        self.assertEqual(event.unifi_source_ip, "10.0.0.9")
        self.assertEqual(event.unifi_site, "default")
        self.assertEqual(event.unifi_host, "udm")

    def test_dns_buffer_error(self) -> None:
        event = self._parse_message("[773999.100000] [STA_TRACKER] DNS buffer error: flags 32")
        self.assertEqual(event.event_type, "dns_buffer_error")
        self.assertEqual(event.event_category, "network_dns")
        self.assertEqual(event.dns_buffer_flags, 32)

    def test_wifi_tx_retry_burst(self) -> None:
        event = self._parse_message(
            "[774000.200000] rai2: StaTXRetryBurstPeriodicExec MAC=76:27:03:0e:78:15 txAttemptCur=5 txAttemptTotal=25 txRetryCur=2 txRetryTotal=7 rssiCur=-61 rssiPrev=-59 lastTxRate=866M burstRatioCur=40 burstRatioTotal=30 burstCnt=3"
        )
        self.assertEqual(event.event_type, "wifi_tx_retry_burst")
        self.assertEqual(event.event_category, "wifi_quality")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.tx_attempts_current, 5)
        self.assertEqual(event.tx_attempts_total, 25)
        self.assertEqual(event.tx_retries_current, 2)
        self.assertEqual(event.tx_retries_total, 7)
        self.assertEqual(event.rssi_current, -61)
        self.assertEqual(event.rssi_previous, -59)
        self.assertEqual(event.last_tx_rate, "866M")
        self.assertEqual(event.burst_ratio_current, 40)
        self.assertEqual(event.burst_ratio_total, 30)
        self.assertEqual(event.burst_count, 3)

    def test_hostapd_sta_remove(self) -> None:
        event = self._parse_message(
            "rai2: STA 76:27:03:0e:78:15 WPA: calling hostapd_drv_sta_remove(), ../src/ap/sta_info.c:ap_free_sta:183"
        )
        self.assertEqual(event.event_type, "hostapd_sta_remove")
        self.assertEqual(event.event_category, "wifi_disconnect")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")

    def test_radius_accounting_start(self) -> None:
        event = self._parse_message(
            "ra1: STA 76:27:03:0e:78:15 RADIUS: starting accounting session 216248ECCA644CED"
        )
        self.assertEqual(event.event_type, "radius_accounting_start")
        self.assertEqual(event.event_category, "wifi_radius")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.mac, "76:27:03:0e:78:15")
        self.assertEqual(event.radio, "ra1")
        self.assertEqual(event.radius_session_id, "216248ECCA644CED")

    def test_sta_tracker_soft_failure(self) -> None:
        event = self._parse_message(
            'stahtd[3888]: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"76:27:03:0e:78:15","vap":"ra1","event_type":"soft failure","assoc_status":"0","ip_assign_type":"roamed","wpa_auth_delta":"88000","assoc_delta":"56000","auth_delta":"0","event_id":"1","auth_ts":"772918.013299","avg_rssi":"-57"}'
        )
        self.assertEqual(event.event_type, "sta_tracker_soft_failure")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.radio, "ra1")
        self.assertEqual(event.assoc_status, "0")
        self.assertEqual(event.ip_assign_type, "roamed")
        self.assertEqual(event.avg_rssi, -57)
        self.assertEqual(event.internal_event_ts, "772918.013299")
        self.assertEqual(event.wpa_auth_delta, "88000")
        self.assertEqual(event.assoc_delta, "56000")
        self.assertEqual(event.auth_delta, "0")

    def test_roaming_decision(self) -> None:
        event = self._parse_message(
            "Ch. 1 (2.4 GHz, 20 MHz), -57 dBm. Roaming Decision: -81 dBm to -57 dBm."
        )
        self.assertEqual(event.event_type, "wifi_roaming_decision")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.channel, 1)
        self.assertEqual(event.band, "2.4 GHz")
        self.assertEqual(event.channel_width, "20 MHz")
        self.assertEqual(event.rssi, -57)
        self.assertEqual(event.roaming_from_rssi, -81)
        self.assertEqual(event.roaming_to_rssi, -57)

    def test_stp_port_status(self) -> None:
        event = self._parse_message(
            "STP-W-PORTSTATUS: te1/0/5: STP status Forwarding"
        )
        self.assertEqual(event.event_type, "stp_port_status")
        self.assertEqual(event.event_category, "network_stp")
        self.assertEqual(event.interface, "te1/0/5")
        self.assertEqual(event.stp_status, "Forwarding")

    def test_kernel_noise_events(self) -> None:
        flush_event = self._parse_message("[772893.250085] cb2, flush one!")
        self.assertEqual(flush_event.event_type, "kernel_flush_event")
        self.assertEqual(flush_event.event_category, "system_event")
        empty_event = self._parse_message("[773365.408224]")
        self.assertEqual(empty_event.event_type, "kernel_empty_message")
        self.assertEqual(empty_event.event_category, "system_event")

    def test_station_idle_probe_sta_dash_format(self) -> None:
        event = self._parse_message(
            "[772916.700301] rai2: Send NULL to STA-76:27:03:0e:78:15 idle(60) timeout(480)"
        )
        self.assertEqual(event.event_type, "station_idle_probe")
        self.assertEqual(event.event_category, "wifi_disconnect")
        self.assertEqual(event.internal_event_ts, "772916.700301")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(event.idle_seconds, 60)
        self.assertEqual(event.timeout_seconds, 480)

    def test_wifi_sta_anomaly_report(self) -> None:
        event = self._parse_message(
            "mcad[3901]: wireless_agg_stats.log_sta_anomalies(): bssid=0e:ea:14:af:a1:59 radio=rai0 vap=rai2 sta=ac:f2:3c:00:18:b5 satisfaction_now=60 anomalies="
        )
        self.assertEqual(event.event_type, "wifi_sta_anomaly_report")
        self.assertEqual(event.event_category, "wifi_quality")
        self.assertEqual(event.ap_mac, "0e:ea:14:af:a1:59")
        self.assertEqual(event.radio, "rai0")
        self.assertEqual(event.vap, "rai2")
        self.assertEqual(event.client_mac, "ac:f2:3c:00:18:b5")
        self.assertEqual(event.satisfaction_now, 60)
        self.assertEqual(event.anomalies, "")

    def test_sta_tracker_roam(self) -> None:
        event = self._parse_message(
            'stahtd[3887]: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"ac:f2:3c:00:18:b5","vap":"rai2","event_type":"sta_roam","assoc_status":"0","event_id":"5"}'
        )
        self.assertEqual(event.event_type, "sta_tracker_roam")
        self.assertEqual(event.event_category, "wifi_roam")
        self.assertEqual(event.client_mac, "ac:f2:3c:00:18:b5")
        self.assertEqual(event.radio, "rai2")
        self.assertEqual(event.assoc_status, "0")
        self.assertEqual(event.sta_tracker_event_id, "5")

    def test_sta_assoc_tracker_failure(self) -> None:
        event = self._parse_message(
            'stahtd[3888]: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"c4:82:e1:71:52:e0","vap":"ra0","event_type":"failure","assoc_status":"0","auth_failures":"18","event_id":"167","auth_ts":"772859.997409"}'
        )
        self.assertEqual(event.event_type, "assoc_tracker_failure")
        self.assertEqual(event.event_category, "wifi_association")
        self.assertEqual(event.client_mac, "c4:82:e1:71:52:e0")
        self.assertEqual(event.mac, "c4:82:e1:71:52:e0")
        self.assertEqual(event.radio, "ra0")
        self.assertEqual(event.internal_event_ts, "772859.997409")
        self.assertEqual(event.internal_event_ts_float, 772859.997409)
        self.assertEqual(event.assoc_status, "0")
        self.assertEqual(event.auth_failures, "18")
        self.assertEqual(event.sta_tracker_event_id, "167")

    def test_wireless_agg_dns_timeout(self) -> None:
        event = self._parse_message(
            "mcad[3901]: wireless_agg_stats.log_sta_anomalies(): bssid=0e:ea:14:af:a1:59 radio=rai0 vap=rai2 sta=ac:f2:3c:00:18:b5 satisfaction_now=60 anomalies=dns_timeout"
        )
        self.assertEqual(event.event_type, "dns_timeout")
        self.assertEqual(event.event_category, "network_dns")
        self.assertEqual(event.ap_mac, "0e:ea:14:af:a1:59")
        self.assertEqual(event.client_mac, "ac:f2:3c:00:18:b5")
        self.assertEqual(event.radio, "rai0")
        self.assertEqual(event.vap, "rai2")
        self.assertEqual(event.satisfaction_now, 60)

    def test_ace_reporter_save_config(self) -> None:
        event = self._parse_message(
            "mcad[3903]: ace_reporter.reporter_save_config(): inform_url: http://10.10.242.231:8080/inform"
        )
        self.assertEqual(event.event_type, "device_config_report")
        self.assertEqual(event.event_category, "device_management")
        self.assertEqual(event.process_name, "mcad")
        self.assertEqual(event.config_key, "inform_url")
        self.assertEqual(event.config_value, "http://10.10.242.231:8080/inform")

    def test_syslogd_and_logread_lifecycle(self) -> None:
        syslogd_line = (
            "10.0.0.1 Apr 23 12:00:00 ap01 daemon info "
            "syslogd[123]: exiting on signal 15"
        )
        logread_line = (
            "10.0.0.1 Apr 23 12:00:01 ap01 daemon info "
            "logread[321]: logread started and listening"
        )
        syslogd_event = parse_line(syslogd_line)
        logread_event = parse_line(logread_line)
        self.assertIsNotNone(syslogd_event)
        self.assertIsNotNone(logread_event)
        self.assertEqual(syslogd_event.event_type, "syslogd_lifecycle")
        self.assertEqual(syslogd_event.event_category, "system_logging")
        self.assertEqual(syslogd_event.process_name, "syslogd")
        self.assertEqual(logread_event.event_type, "logread_lifecycle")
        self.assertEqual(logread_event.event_category, "system_logging")
        self.assertEqual(logread_event.process_name, "logread")

    def test_dhcp_assignment_and_link_state(self) -> None:
        dhcp_event = self._parse_message("dnsmasq-dhcp: DHCPACK(br0) 192.168.1.10 aa:bb:cc:dd:ee:ff")
        link_up = self._parse_message("br-lan: link has become up")
        link_down = self._parse_message("eth0: link down")

        self.assertEqual(dhcp_event.event_type, "dhcp_ip_assignment")
        self.assertEqual(dhcp_event.event_category, "network_dhcp")
        self.assertEqual(dhcp_event.client_mac, "aa:bb:cc:dd:ee:ff")

        self.assertEqual(link_up.event_type, "network_link_up")
        self.assertEqual(link_up.event_category, "network_link")
        self.assertEqual(link_down.event_type, "network_link_down")
        self.assertEqual(link_down.event_category, "network_link")

    def test_config_and_management_classification(self) -> None:
        setparam = self._parse_message("mcad setparam inform_url=http://10.0.0.2:8080/inform")
        apply_cfg = self._parse_message("syswrapper: fast apply complete")
        cfg_save = self._parse_message("mca-monitor: need_cfg_save in system.cfg")

        self.assertEqual(setparam.event_type, "config_setparam")
        self.assertEqual(setparam.event_category, "device_config")
        self.assertEqual(setparam.config_key, "inform_url")
        self.assertEqual(setparam.config_value, "http://10.0.0.2:8080/inform")

        self.assertEqual(apply_cfg.event_type, "config_apply")
        self.assertEqual(apply_cfg.event_category, "device_config")

        self.assertEqual(cfg_save.event_type, "config_save_required")
        self.assertEqual(cfg_save.event_category, "device_config")

    def test_wifi_additional_patterns(self) -> None:
        join = self._parse_message("EVENT_STA_JOIN radio=ra1 sta=76:27:03:0e:78:15")
        associated = self._parse_message("ra1: STA 76:27:03:0e:78:15 associated")
        handshake = self._parse_message("ra1: pairwise key handshake completed for 76:27:03:0e:78:15")
        sta_ip = self._parse_message("EVENT_STA_IP ra1 STA 76:27:03:0e:78:15 ip=192.168.1.77")

        self.assertEqual(join.event_type, "client_join")
        self.assertEqual(join.event_category, "wifi_association")
        self.assertEqual(join.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(join.radio, "ra1")

        self.assertEqual(associated.event_type, "client_associated")
        self.assertEqual(associated.client_mac, "76:27:03:0e:78:15")
        self.assertEqual(associated.radio, "ra1")

        self.assertEqual(handshake.event_type, "handshake_completed")
        self.assertEqual(handshake.event_category, "wifi_security")
        self.assertEqual(handshake.client_mac, "76:27:03:0e:78:15")

        self.assertEqual(sta_ip.event_type, "client_ip_assigned")
        self.assertEqual(sta_ip.event_category, "wifi_client_ip")
        self.assertEqual(sta_ip.client_ip, "192.168.1.77")
        self.assertEqual(sta_ip.client_mac, "76:27:03:0e:78:15")

    def test_link_and_process_lifecycle_patterns(self) -> None:
        link_i_up = self._parse_message("eth1: LINK-I-Up")
        link_w_down = self._parse_message("eth1 port 2: LINK-W-Down")
        syslog_args = self._parse_message("syslogd arguments changed, restarting")
        sigterm_timeout = self._parse_message("procd: Process didn't stop on SIGTERM")

        self.assertEqual(link_i_up.event_type, "link_up")
        self.assertEqual(link_i_up.event_category, "network_link")
        self.assertEqual(link_i_up.interface, "eth1")
        self.assertEqual(link_i_up.link_state, "up")

        self.assertEqual(link_w_down.event_type, "link_down")
        self.assertEqual(link_w_down.port, 2)
        self.assertEqual(link_w_down.link_state, "down")

        self.assertEqual(syslog_args.event_type, "logging_config_changed")
        self.assertEqual(syslog_args.event_category, "system_logging")

        self.assertEqual(sigterm_timeout.event_type, "process_sigterm_timeout")
        self.assertEqual(sigterm_timeout.event_category, "process_lifecycle")


if __name__ == "__main__":
    unittest.main()
