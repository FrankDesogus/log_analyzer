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
    return None


def classify_event_category(
    message: str,
    process_name: Optional[str],
    event_type: Optional[str],
) -> str:
    """Map event_type/message/process_name to a broader event category."""
    if event_type in {"auth_request", "auth_response"}:
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
