import re
from typing import Optional


EVENT_STA_LEAVE_RE = re.compile(r"\bEVENT_STA_LEAVE\b")
STA_LEAVE_RE = re.compile(r"\bSTA_LEAVE\b")
DISASSOCIATED_RE = re.compile(r"\bdisassociated\b", re.IGNORECASE)
RECV_AUTH_REQ_RE = re.compile(r"\brecv(?:_|\s+)auth_req\b", re.IGNORECASE)
SEND_AUTH_RSP_RE = re.compile(r"\bsend(?:_|\s+)auth_rsp\b", re.IGNORECASE)
ROAM_RE = re.compile(r"\b(?:sta_roam|roam)\b", re.IGNORECASE)
IP_EVENT_RE = re.compile(r"\b(?:EVENT_STA_IP|sta_ip)\b", re.IGNORECASE)
CONTROLLER_CONFIG_RE = re.compile(
    r"\b(?:save\s*config|apply\s*config|reporter\s*config|controller\s*config|provision(?:ing)?)\b",
    re.IGNORECASE,
)
DEVICE_MGMT_RE = re.compile(
    r"\b(?:adopt(?:ed|ion)?|upgrade|reboot|inform|manage(?:ment)?)\b",
    re.IGNORECASE,
)
SYSTEM_EVENT_RE = re.compile(
    r"\b(?:kernel|systemd|cron|dhcp|ntp|dns|firewall|boot|service)\b",
    re.IGNORECASE,
)
DNS_TIMEOUT_RE = re.compile(r"\bDNS request timed out\b", re.IGNORECASE)
WIFI_SCAN_SANITY_FAILED_RE = re.compile(
    r"\bubnt_get_scan_result:\s*sanity check failed,\s*invalid BssEntry\b",
    re.IGNORECASE,
)
DROP_CACHES_RE = re.compile(r"\bdrop_caches:\s*\d+\b", re.IGNORECASE)
CFG80211_STA_DEL_START_RE = re.compile(r"CFG80211_OpsStaDel\s*==>", re.IGNORECASE)
CFG80211_STA_DEL_END_RE = re.compile(r"CFG80211_OpsStaDel\s*<==", re.IGNORECASE)
EAP_PACKET_RE = re.compile(r"\bRTMPCheckEtherType\(\)\s*==>\s*EAP Packet\b", re.IGNORECASE)
STA_ASSOC_TRACKER_DNS_TIMEOUT_RE = re.compile(
    r'STA_ASSOC_TRACKER".*?"event_type"\s*:\s*"dns timeout"',
    re.IGNORECASE,
)
REASSOC_REQ_RE = re.compile(r"\[recv\s+reassoc_req\]", re.IGNORECASE)
CFG80211_ASSOC_REQ_HANDLER_RE = re.compile(r"\bCFG80211_AssocReqHandler\b", re.IGNORECASE)
EAPOL_PACKET_RE = re.compile(r"\brt28xx_send_packets\s+Send\s+EAPOL\s+of\s+length\s+\d+", re.IGNORECASE)
EAPOL_KEY_RE = re.compile(r"\b(?:Send|Recv)\s+EAPOL-Key\s+M[1-4]\b", re.IGNORECASE)
WIFI_KEY_ADD_STA_RE = re.compile(r"\bKeyAdd\s+STA\(", re.IGNORECASE)
WIFI_KEY_DEL_STA_RE = re.compile(r"\bKeyDel\s+STA\(", re.IGNORECASE)
WIFI_AP_KEY_ADD_RE = re.compile(r"\bAP\s+Key\s+Add\b", re.IGNORECASE)
DELETE_STA_RE = re.compile(r"\bDelete\s+STA\(", re.IGNORECASE)
CFG80211_AP_STA_DEL_RE = re.compile(r"\bCFG80211_ApStaDel\b.*\bSTA_DEL\b", re.IGNORECASE)
SEND_DEAUTH_RE = re.compile(r"\[send\s+deauth\]", re.IGNORECASE)
RADIUS_ENTRY_DEL_RE = re.compile(r"\bradius\s+entry\[\d+\]\s+DEL\s+\(", re.IGNORECASE)
DRIVER_MISSING_STATION_ENTRY_RE = re.compile(r"Can't find pEntry in ", re.IGNORECASE)


def classify_event_type(message: str) -> Optional[str]:
    """Normalize known message patterns into stable event types."""
    if EVENT_STA_LEAVE_RE.search(message) or STA_LEAVE_RE.search(message):
        return "disconnect"
    if DISASSOCIATED_RE.search(message):
        return "disconnect"
    if RECV_AUTH_REQ_RE.search(message):
        return "auth_request"
    if SEND_AUTH_RSP_RE.search(message):
        return "auth_response"
    if DNS_TIMEOUT_RE.search(message):
        return "dns_timeout"
    if STA_ASSOC_TRACKER_DNS_TIMEOUT_RE.search(message):
        return "dns_timeout"
    if REASSOC_REQ_RE.search(message):
        return "reassoc_request"
    if CFG80211_ASSOC_REQ_HANDLER_RE.search(message):
        return "cfg80211_assoc_request_handler"
    if EAPOL_KEY_RE.search(message):
        return "eapol_key"
    if EAPOL_PACKET_RE.search(message):
        return "eapol_packet"
    if WIFI_KEY_ADD_STA_RE.search(message):
        return "wifi_key_add"
    if WIFI_KEY_DEL_STA_RE.search(message):
        return "wifi_key_delete"
    if WIFI_AP_KEY_ADD_RE.search(message):
        return "wifi_ap_key_add"
    if DELETE_STA_RE.search(message):
        return "station_delete"
    if CFG80211_AP_STA_DEL_RE.search(message):
        return "cfg80211_station_delete"
    if SEND_DEAUTH_RE.search(message):
        return "deauth_sent"
    if RADIUS_ENTRY_DEL_RE.search(message):
        return "radius_entry_delete"
    if DRIVER_MISSING_STATION_ENTRY_RE.search(message):
        return "driver_missing_station_entry"
    if WIFI_SCAN_SANITY_FAILED_RE.search(message):
        return "wifi_scan_error"
    if DROP_CACHES_RE.search(message):
        return "system_cache_drop"
    if CFG80211_STA_DEL_START_RE.search(message):
        return "cfg80211_station_delete_start"
    if CFG80211_STA_DEL_END_RE.search(message):
        return "cfg80211_station_delete_end"
    if EAP_PACKET_RE.search(message):
        return "eap_packet"
    return None


def classify_event_category(
    message: str,
    process_name: Optional[str],
    event_type: Optional[str],
) -> str:
    """Map event_type/message/process_name to a broader event category."""
    if event_type in {"auth_request", "auth_response"}:
        return "wifi_auth"
    if event_type == "dns_timeout":
        return "network_dns"
    if event_type == "wifi_scan_error":
        return "wifi_system"
    if event_type in {"reassoc_request"}:
        return "wifi_roam"
    if event_type in {"cfg80211_assoc_request_handler", "driver_missing_station_entry"}:
        return "wifi_driver"
    if event_type in {"eapol_packet", "eapol_key"}:
        return "wifi_eapol"
    if event_type in {"wifi_key_add", "wifi_key_delete", "wifi_ap_key_add"}:
        return "wifi_security"
    if event_type in {
        "station_delete",
        "cfg80211_station_delete",
        "deauth_sent",
        "radius_entry_delete",
    }:
        return "wifi_disconnect"
    if event_type == "system_cache_drop":
        return "system_maintenance"
    if event_type in {"cfg80211_station_delete_start", "cfg80211_station_delete_end"}:
        return "wifi_driver"
    if event_type == "eap_packet":
        return "wifi_auth"
    if event_type == "disconnect":
        return "wifi_disconnect"

    if ROAM_RE.search(message):
        return "wifi_roam"
    if IP_EVENT_RE.search(message):
        return "wifi_ip_event"

    haystack = f"{process_name or ''} {message}"
    if CONTROLLER_CONFIG_RE.search(haystack):
        return "controller_config"
    if DEVICE_MGMT_RE.search(haystack):
        return "device_management"
    if SYSTEM_EVENT_RE.search(haystack):
        return "system_event"

    return "unknown"
