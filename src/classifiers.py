import re
from typing import Optional


EVENT_STA_LEAVE_RE = re.compile(r"\bEVENT_STA_LEAVE\b")
STA_LEAVE_RE = re.compile(r"\bSTA_LEAVE\b")
DISASSOCIATED_RE = re.compile(r"\bdisassociated\b", re.IGNORECASE)
RECV_AUTH_REQ_RE = re.compile(r"\brecv(?:_|\s+)auth_req\b", re.IGNORECASE)
SEND_AUTH_RSP_RE = re.compile(r"\bsend(?:_|\s+)auth_rsp\b", re.IGNORECASE)


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
