from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


INTERNAL_TS_MAX_GAP_SECONDS = 1.5
MIXED_TS_MAX_LINE_GAP = 3
NORMALIZED_TS_MAX_LINE_GAP = 2
WIFI_SEQUENCE_TYPES = {"auth_request", "auth_response", "disconnect"}


@dataclass
class _ClusterState:
    source_ip: Optional[str]
    client_mac: Optional[str]
    radio: Optional[str]
    host: Optional[str] = None
    ap_mac: Optional[str] = None
    raw_indexes: list[int] = field(default_factory=list)
    raw_line_numbers: list[int] = field(default_factory=list)
    event_types: set[str] = field(default_factory=set)
    event_categories: set[str] = field(default_factory=set)
    process_names: set[str] = field(default_factory=set)
    sources_seen: set[str] = field(default_factory=set)
    first_normalized_timestamp: Optional[str] = None
    first_internal_event_ts: Optional[float] = None
    last_internal_event_ts: Optional[float] = None
    last_internal_event_ts_for_gap: Optional[float] = None
    last_normalized_epoch_for_gap: Optional[float] = None
    last_line_number_for_gap: Optional[int] = None


def build_canonical_events(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Build conservative canonical correlated events without altering raw records."""
    clusters: list[_ClusterState] = []

    indexed_events: list[tuple[int, dict[str, Any]]] = list(enumerate(events))
    indexed_events.sort(key=lambda item: _sort_key(item[0], item[1]))

    for raw_index, event in indexed_events:
        attached = False
        for cluster in reversed(clusters):
            if not _same_identity(cluster, event):
                continue
            if not _is_event_compatible(cluster, event):
                continue
            if not _within_time_window(cluster, event):
                continue

            _add_event_to_cluster(cluster, raw_index, event)
            attached = True
            break

        if not attached:
            cluster = _new_cluster(raw_index, event)
            clusters.append(cluster)

    canonical_events = [
        _cluster_to_canonical_event(cluster, canonical_index)
        for canonical_index, cluster in enumerate(clusters, start=1)
    ]

    return {
        "raw_events": list(events),
        "canonical_events": canonical_events,
    }


def _sort_key(raw_index: int, event: dict[str, Any]) -> tuple[str, str, str, int, float, int]:
    source_ip = event.get("source_ip") or ""
    client_mac = event.get("client_mac") or ""
    radio = event.get("radio") or ""

    internal_ts = event.get("internal_event_ts_float")
    normalized_epoch = _normalized_ts_to_epoch(event.get("normalized_timestamp"))

    if internal_ts is not None:
        order_class = 0
        ts_value = float(internal_ts)
    elif normalized_epoch is not None:
        order_class = 1
        ts_value = normalized_epoch
    else:
        order_class = 2
        ts_value = float(raw_index)

    return (source_ip, client_mac, radio, order_class, ts_value, raw_index)


def _same_identity(cluster: _ClusterState, event: dict[str, Any]) -> bool:
    return (
        cluster.source_ip == event.get("source_ip")
        and cluster.client_mac == event.get("client_mac")
        and cluster.radio == event.get("radio")
    )


def _is_event_compatible(cluster: _ClusterState, event: dict[str, Any]) -> bool:
    event_type = event.get("event_type")
    if not cluster.event_types:
        return True

    if event_type is None:
        return True

    if event_type in WIFI_SEQUENCE_TYPES:
        return all(t in WIFI_SEQUENCE_TYPES for t in cluster.event_types)

    return event_type in cluster.event_types


def _within_time_window(cluster: _ClusterState, event: dict[str, Any]) -> bool:
    current_internal = event.get("internal_event_ts_float")
    current_line = event.get("line_number")
    current_normalized = _normalized_ts_to_epoch(event.get("normalized_timestamp"))

    if cluster.last_internal_event_ts_for_gap is not None and current_internal is not None:
        return abs(float(current_internal) - cluster.last_internal_event_ts_for_gap) <= INTERNAL_TS_MAX_GAP_SECONDS

    if cluster.last_internal_event_ts_for_gap is not None or current_internal is not None:
        if current_line is None or cluster.last_line_number_for_gap is None:
            return False
        return abs(int(current_line) - cluster.last_line_number_for_gap) <= MIXED_TS_MAX_LINE_GAP

    if cluster.last_normalized_epoch_for_gap is None or current_normalized is None:
        return False

    if int(cluster.last_normalized_epoch_for_gap) != int(current_normalized):
        return False

    if current_line is None or cluster.last_line_number_for_gap is None:
        return False

    return abs(int(current_line) - cluster.last_line_number_for_gap) <= NORMALIZED_TS_MAX_LINE_GAP


def _new_cluster(raw_index: int, event: dict[str, Any]) -> _ClusterState:
    cluster = _ClusterState(
        source_ip=event.get("source_ip"),
        client_mac=event.get("client_mac"),
        radio=event.get("radio"),
    )
    _add_event_to_cluster(cluster, raw_index, event)
    return cluster


def _add_event_to_cluster(cluster: _ClusterState, raw_index: int, event: dict[str, Any]) -> None:
    cluster.raw_indexes.append(raw_index)
    line_number = event.get("line_number")
    if line_number is not None:
        cluster.raw_line_numbers.append(int(line_number))

    if cluster.host is None and event.get("host") is not None:
        cluster.host = event.get("host")
    if cluster.ap_mac is None and event.get("ap_mac") is not None:
        cluster.ap_mac = event.get("ap_mac")

    event_type = event.get("event_type")
    if event_type:
        cluster.event_types.add(event_type)

    event_category = event.get("event_category")
    if event_category:
        cluster.event_categories.add(event_category)

    process_name = event.get("process_name")
    if process_name:
        cluster.process_names.add(process_name)

    process = event.get("process")
    if process:
        cluster.sources_seen.add(process)

    normalized_timestamp = event.get("normalized_timestamp")
    if cluster.first_normalized_timestamp is None and normalized_timestamp is not None:
        cluster.first_normalized_timestamp = normalized_timestamp

    internal_ts = event.get("internal_event_ts_float")
    if internal_ts is not None:
        internal_ts_float = float(internal_ts)
        if cluster.first_internal_event_ts is None or internal_ts_float < cluster.first_internal_event_ts:
            cluster.first_internal_event_ts = internal_ts_float
        if cluster.last_internal_event_ts is None or internal_ts_float > cluster.last_internal_event_ts:
            cluster.last_internal_event_ts = internal_ts_float
        cluster.last_internal_event_ts_for_gap = internal_ts_float

    normalized_epoch = _normalized_ts_to_epoch(normalized_timestamp)
    if normalized_epoch is not None:
        cluster.last_normalized_epoch_for_gap = normalized_epoch

    if line_number is not None:
        cluster.last_line_number_for_gap = int(line_number)


def _cluster_to_canonical_event(cluster: _ClusterState, canonical_index: int) -> dict[str, Any]:
    duration_ms: Optional[int] = None
    if cluster.first_internal_event_ts is not None and cluster.last_internal_event_ts is not None:
        duration_ms = int(round((cluster.last_internal_event_ts - cluster.first_internal_event_ts) * 1000))

    return {
        "canonical_event_id": f"ce-{canonical_index:06d}",
        "source_ip": cluster.source_ip,
        "host": cluster.host,
        "client_mac": cluster.client_mac,
        "ap_mac": cluster.ap_mac,
        "radio": cluster.radio,
        "normalized_timestamp": cluster.first_normalized_timestamp,
        "first_internal_event_ts": cluster.first_internal_event_ts,
        "last_internal_event_ts": cluster.last_internal_event_ts,
        "duration_ms": duration_ms,
        "raw_event_count": len(cluster.raw_indexes),
        "raw_line_numbers": sorted(cluster.raw_line_numbers),
        "raw_event_indexes": cluster.raw_indexes,
        "event_types_seen": sorted(cluster.event_types),
        "event_categories_seen": sorted(cluster.event_categories),
        "process_names_seen": sorted(cluster.process_names),
        "sources_seen": sorted(cluster.sources_seen),
        "correlation_strategy": {
            "name": "conservative_v1",
            "identity_fields": ["source_ip", "client_mac", "radio"],
            "time_priority": "internal_event_ts_float",
        },
        "canonical_event_type": _derive_canonical_event_type(cluster.event_types),
    }


def _derive_canonical_event_type(event_types: set[str]) -> str:
    if not event_types:
        return "wifi_unknown_sequence"

    has_auth = "auth_request" in event_types or "auth_response" in event_types
    has_disconnect = "disconnect" in event_types

    if has_auth and has_disconnect:
        return "wifi_auth_disconnect_sequence"
    if has_auth:
        return "wifi_auth_sequence"
    if has_disconnect:
        return "wifi_disconnect_sequence"

    if len(event_types) == 1:
        only_type = next(iter(event_types))
        return f"wifi_{only_type}_sequence"

    return "wifi_mixed_sequence"


def _normalized_ts_to_epoch(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None
