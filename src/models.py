from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass
class ParsedEvent:
    parse_status: str
    raw_line: str
    line_number: Optional[int] = None
    source_ip: Optional[str] = None
    timestamp: Optional[str] = None
    host: Optional[str] = None
    facility: Optional[str] = None
    severity: Optional[str] = None
    process: Optional[str] = None
    raw_message: Optional[str] = None
    event_type: Optional[str] = None
    mac: Optional[str] = None
    radio: Optional[str] = None
    rssi: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
