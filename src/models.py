from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass
class ParsedEvent:
    parse_status: str
    raw_line: str
    line_number: Optional[int] = None
    source_ip: Optional[str] = None
    timestamp: Optional[str] = None
    original_timestamp: Optional[str] = None
    normalized_timestamp: Optional[str] = None
    host: Optional[str] = None
    facility: Optional[str] = None
    severity: Optional[str] = None
    process: Optional[str] = None
    process_name: Optional[str] = None
    raw_message: Optional[str] = None
    event_type: Optional[str] = None
    event_category: Optional[str] = None
    mac: Optional[str] = None
    client_mac: Optional[str] = None
    ap_mac: Optional[str] = None
    radio: Optional[str] = None
    rssi: Optional[int] = None
    duplicate_group_key: Optional[str] = None
    is_duplicate_candidate: bool = False
    duplicate_group_size: int = 1
    internal_event_ts: Optional[str] = None
    internal_event_ts_float: Optional[float] = None
    internal_event_bucket: Optional[str] = None
    query: Optional[str] = None
    dns_server: Optional[str] = None
    transaction_id: Optional[str] = None
    source_port: Optional[int] = None
    error_type: Optional[str] = None
    drop_caches_value: Optional[int] = None
    bssid: Optional[str] = None
    port_secure: Optional[int] = None
    clear_frame: Optional[int] = None
    dns_queries: Optional[list[str]] = None
    dns_servers: Optional[list[str]] = None
    assoc_status: Optional[str] = None
    tracker_message_type: Optional[str] = None
    eapol_direction: Optional[str] = None
    eapol_length: Optional[int] = None
    eapol_source: Optional[str] = None
    eapol_message: Optional[str] = None
    da_mac: Optional[str] = None
    sa_mac: Optional[str] = None
    reason: Optional[str] = None
    protection: Optional[int] = None
    driver_context: Optional[str] = None
    aid: Optional[int] = None
    wcid: Optional[int] = None
    entry_type: Optional[int] = None
    phy: Optional[str] = None
    bandwidth: Optional[str] = None
    mcs: Optional[str] = None
    wmm: Optional[str] = None
    rrm: Optional[str] = None
    duration_usec: Optional[int] = None
    qos_map_support: Optional[int] = None
    idle_seconds: Optional[int] = None
    timeout_seconds: Optional[int] = None
    fine_duplicate_group_key: Optional[str] = None
    fine_duplicate_group_size: int = 1
    is_fine_duplicate_candidate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
