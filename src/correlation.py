from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


DEFAULT_MAX_GAP_MS = 15
CORRELATION_STRATEGY = "source_ip+client_mac+radio_or_fallback+internal_event_ts_window"


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
    event_type_counts: dict[str, int] = field(default_factory=dict)
    event_categories: set[str] = field(default_factory=set)
    process_names: set[str] = field(default_factory=set)
    sources_seen: set[str] = field(default_factory=set)
    first_normalized_timestamp: Optional[str] = None
    first_internal_event_ts: Optional[float] = None
    last_internal_event_ts: Optional[float] = None
    first_sort_ts: Optional[float] = None
    last_sort_ts: Optional[float] = None
    rssi_values: list[int] = field(default_factory=list)


def build_canonical_events(events: list[dict[str, Any]], max_gap_ms: int = DEFAULT_MAX_GAP_MS) -> dict[str, list[dict[str, Any]]]:
    """Build canonical SIEM-like WiFi sequences from normalized raw events.

    Raw events are kept untouched and returned as-is in `raw_events`.
    """
    identity_groups: dict[tuple[str, str, str], list[tuple[int, dict[str, Any]]]] = {}

    for raw_index, event in enumerate(events):
        identity = _group_identity(event)
        identity_groups.setdefault(identity, []).append((raw_index, event))

    clusters: list[_ClusterState] = []
    for group_events in identity_groups.values():
        sorted_group = sorted(group_events, key=lambda item: _event_sort_key(item[0], item[1]))
        clusters.extend(_build_group_clusters(sorted_group, max_gap_ms=max_gap_ms))

    clusters.sort(key=lambda cluster: _cluster_sort_key(cluster))

    canonical_events = [
        _cluster_to_canonical_event(cluster, canonical_index)
        for canonical_index, cluster in enumerate(clusters, start=1)
    ]

    return {
        "raw_events": list(events),
        "canonical_events": canonical_events,
    }


def _group_identity(event: dict[str, Any]) -> tuple[str, str, str]:
    source_ip = str(event.get("source_ip") or "")
    client_mac = str(event.get("client_mac") or "")
    radio = str(event.get("radio") or "")
    if client_mac and radio:
        return (source_ip, client_mac, radio)
    process_name = str(event.get("process_name") or "")
    event_type = str(event.get("event_type") or "")
    return (source_ip, f"fallback:{process_name}", f"fallback:{event_type}")


def _event_sort_key(raw_index: int, event: dict[str, Any]) -> tuple[int, float, int]:
    ts = _event_sort_ts(event)
    if ts is None:
        return (2, float(raw_index), raw_index)

    if event.get("internal_event_ts_float") is not None:
        return (0, ts, raw_index)

    return (1, ts, raw_index)


def _event_sort_ts(event: dict[str, Any]) -> Optional[float]:
    internal_ts = _to_float_or_none(event.get("internal_event_ts_float"))
    if internal_ts is not None:
        return internal_ts

    return _normalized_ts_to_epoch(event.get("normalized_timestamp"))


def _build_group_clusters(
    sorted_group_events: list[tuple[int, dict[str, Any]]],
    max_gap_ms: int,
) -> list[_ClusterState]:
    clusters: list[_ClusterState] = []
    active_cluster: Optional[_ClusterState] = None

    for raw_index, event in sorted_group_events:
        if active_cluster is None:
            active_cluster = _new_cluster(raw_index, event)
            continue

        if _can_attach_to_cluster(active_cluster, event, max_gap_ms=max_gap_ms):
            _add_event_to_cluster(active_cluster, raw_index, event)
            continue

        clusters.append(active_cluster)
        active_cluster = _new_cluster(raw_index, event)

    if active_cluster is not None:
        clusters.append(active_cluster)

    return clusters


def _can_attach_to_cluster(cluster: _ClusterState, event: dict[str, Any], max_gap_ms: int) -> bool:
    cluster_last_ts = cluster.last_sort_ts
    event_ts = _event_sort_ts(event)

    # Nessun riferimento temporale affidabile: separazione prudente.
    if cluster_last_ts is None or event_ts is None:
        return False

    gap_seconds = abs(event_ts - cluster_last_ts)
    if gap_seconds * 1000 <= max_gap_ms:
        return True

    # Fallback prudente quando manca internal_event_ts_float sul nuovo evento:
    # consenti accorpamento solo in caso di allineamento quasi perfetto sul timestamp normalizzato.
    if event.get("internal_event_ts_float") is None:
        cluster_norm = cluster.first_normalized_timestamp
        event_norm = event.get("normalized_timestamp")
        if cluster_norm and event_norm and cluster_norm == event_norm and gap_seconds <= 0.001:
            return True

    return False


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
        event_type_str = str(event_type)
        cluster.event_types.add(event_type_str)
        cluster.event_type_counts[event_type_str] = cluster.event_type_counts.get(event_type_str, 0) + 1

    event_category = event.get("event_category")
    if event_category:
        cluster.event_categories.add(str(event_category))

    process_name = event.get("process_name")
    if process_name:
        cluster.process_names.add(str(process_name))

    process = event.get("process")
    if process:
        cluster.sources_seen.add(str(process))

    normalized_timestamp = event.get("normalized_timestamp")
    if cluster.first_normalized_timestamp is None and normalized_timestamp is not None:
        cluster.first_normalized_timestamp = str(normalized_timestamp)

    internal_ts = _to_float_or_none(event.get("internal_event_ts_float"))
    if internal_ts is not None:
        if cluster.first_internal_event_ts is None or internal_ts < cluster.first_internal_event_ts:
            cluster.first_internal_event_ts = internal_ts
        if cluster.last_internal_event_ts is None or internal_ts > cluster.last_internal_event_ts:
            cluster.last_internal_event_ts = internal_ts

    event_sort_ts = _event_sort_ts(event)
    if event_sort_ts is not None:
        if cluster.first_sort_ts is None:
            cluster.first_sort_ts = event_sort_ts
        cluster.last_sort_ts = event_sort_ts

    rssi_value = _to_int_or_none(event.get("rssi"))
    if rssi_value is not None:
        cluster.rssi_values.append(rssi_value)


def _cluster_sort_key(cluster: _ClusterState) -> tuple[int, float, int]:
    if cluster.first_sort_ts is not None:
        return (0, cluster.first_sort_ts, cluster.raw_indexes[0])
    return (1, float(cluster.raw_indexes[0]), cluster.raw_indexes[0])


def _cluster_to_canonical_event(cluster: _ClusterState, canonical_index: int) -> dict[str, Any]:
    duration_ms: Optional[int] = None
    if cluster.first_internal_event_ts is not None and cluster.last_internal_event_ts is not None:
        duration_ms = int(round((cluster.last_internal_event_ts - cluster.first_internal_event_ts) * 1000))

    event_types_seen = sorted(cluster.event_types)
    sequence_summary = _build_sequence_summary(cluster)

    return {
        "canonical_event_id": _build_canonical_event_id(cluster, canonical_index),
        "canonical_event_type": _derive_canonical_event_type(
            cluster.event_types,
            event_categories=cluster.event_categories,
            process_names=cluster.process_names,
        ),
        "correlation_strategy": CORRELATION_STRATEGY,
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
        "event_types_seen": event_types_seen,
        "event_categories_seen": sorted(cluster.event_categories),
        "process_names_seen": sorted(cluster.process_names),
        "sources_seen": sorted(cluster.sources_seen),
        "sequence_summary": sequence_summary,
    }


def _build_canonical_event_id(cluster: _ClusterState, canonical_index: int) -> str:
    source_ip = (cluster.source_ip or "unknown").replace(":", "")
    client_mac = (cluster.client_mac or "unknown").replace(":", "")
    radio = cluster.radio or "unknown"

    if cluster.first_internal_event_ts is not None:
        first_ts = str(int(round(cluster.first_internal_event_ts * 1000)))
    elif cluster.first_sort_ts is not None:
        first_ts = str(int(round(cluster.first_sort_ts * 1000)))
    else:
        first_ts = f"idx{canonical_index}"

    return f"canon-{source_ip}-{client_mac}-{radio}-{first_ts}"


def _derive_canonical_event_type(
    event_types: set[str],
    event_categories: Optional[set[str]] = None,
    process_names: Optional[set[str]] = None,
) -> str:
    if not event_types:
        return "wifi_unknown_sequence"

    known_event_types = {event_type for event_type in event_types if event_type != "unknown"}
    if not known_event_types:
        return "wifi_unknown_sequence"

    has_auth = "auth_request" in event_types or "auth_response" in event_types
    has_disconnect = "disconnect" in event_types
    has_eapol_flow = any(event_type in {"eapol_key", "eapol_packet", "eap_packet"} for event_type in event_types)
    has_assoc_flow = any(
        event_type
        in {
            "station_join",
            "assoc_success",
            "reassoc_request",
            "reassoc_response",
            "station_table_insert",
            "cfg80211_assoc_request_handler",
            "station_qos_map_support",
        }
        for event_type in event_types
    )
    has_assoc_failure = "assoc_tracker_failure" in event_types
    has_roam_flow = any(
        event_type
        in {
            "reassoc_request",
            "reassoc_response",
            "assoc_success",
            "reassoc_processing_time",
            "fast_transition_roam",
            "rrm_neighbor_response",
        }
        for event_type in event_types
    )
    has_dns_anomaly = "dns_timeout" in event_types
    has_device_mgmt_report = "device_config_report" in event_types
    has_wifi_scan_error = "wifi_scan_error" in event_types
    has_system_maintenance = "system_cache_drop" in event_types
    process_names_normalized = {name.lower() for name in (process_names or set())}
    has_device_mgmt_process = bool({"mcad", "syswrapper", "logread", "procd"} & process_names_normalized)
    has_device_mgmt_category = bool({"device_management", "controller_config"} & set(event_categories or set()))
    has_disconnect_flow = any(
        event_type
        in {
            "station_delete",
            "cfg80211_station_delete",
            "cfg80211_station_delete_start",
            "cfg80211_station_delete_end",
            "station_table_delete",
            "driver_missing_station_entry",
            "deauth_sent",
            "wifi_key_delete",
            "disconnect",
        }
        for event_type in event_types
    )

    if has_auth and has_disconnect:
        return "wifi_auth_disconnect_sequence"
    if has_auth and has_disconnect_flow:
        return "wifi_auth_disconnect_sequence"
    if has_eapol_flow:
        return "wifi_eapol_handshake_sequence"
    if has_system_maintenance:
        return "system_maintenance_sequence"
    if has_wifi_scan_error:
        return "wifi_system_sequence"
    if has_device_mgmt_report or has_device_mgmt_process or has_device_mgmt_category:
        return "device_management_sequence"
    if has_assoc_failure and (has_auth or has_disconnect or has_disconnect_flow):
        return "wifi_auth_disconnect_sequence"
    if has_assoc_failure:
        return "wifi_assoc_failure_sequence"
    if has_roam_flow:
        return "wifi_roam_sequence"
    if has_dns_anomaly:
        return "network_dns_anomaly_sequence"
    if has_assoc_flow:
        return "wifi_association_sequence"
    if has_auth and not has_disconnect:
        return "wifi_auth_sequence"
    if has_disconnect and event_types.issubset({"disconnect"}):
        return "wifi_disconnect_sequence"
    if has_disconnect_flow:
        return "wifi_disconnect_sequence"

    return "wifi_unknown_sequence"


def _build_sequence_summary(cluster: _ClusterState) -> dict[str, Any]:
    auth_request_count = cluster.event_type_counts.get("auth_request", 0)
    auth_response_count = cluster.event_type_counts.get("auth_response", 0)
    disconnect_count = cluster.event_type_counts.get("disconnect", 0)
    eapol_key_count = cluster.event_type_counts.get("eapol_key", 0)
    station_delete_count = cluster.event_type_counts.get("station_delete", 0)
    cfg80211_station_delete_count = cluster.event_type_counts.get("cfg80211_station_delete", 0)
    deauth_sent_count = cluster.event_type_counts.get("deauth_sent", 0)
    station_join_count = cluster.event_type_counts.get("station_join", 0)
    assoc_success_count = cluster.event_type_counts.get("assoc_success", 0)
    reassoc_request_count = cluster.event_type_counts.get("reassoc_request", 0)
    reassoc_response_count = cluster.event_type_counts.get("reassoc_response", 0)
    fast_transition_roam_count = cluster.event_type_counts.get("fast_transition_roam", 0)
    assoc_tracker_failure_count = cluster.event_type_counts.get("assoc_tracker_failure", 0)
    dns_timeout_count = cluster.event_type_counts.get("dns_timeout", 0)
    device_config_report_count = cluster.event_type_counts.get("device_config_report", 0)

    summary = {
        "auth_request_count": auth_request_count,
        "auth_response_count": auth_response_count,
        "disconnect_count": disconnect_count,
        "eapol_key_count": eapol_key_count,
        "station_delete_count": station_delete_count,
        "cfg80211_station_delete_count": cfg80211_station_delete_count,
        "deauth_sent_count": deauth_sent_count,
        "station_join_count": station_join_count,
        "assoc_success_count": assoc_success_count,
        "reassoc_request_count": reassoc_request_count,
        "reassoc_response_count": reassoc_response_count,
        "fast_transition_roam_count": fast_transition_roam_count,
        "assoc_tracker_failure_count": assoc_tracker_failure_count,
        "dns_timeout_count": dns_timeout_count,
        "device_config_report_count": device_config_report_count,
        "rssi_values": list(cluster.rssi_values),
        "rssi_min": min(cluster.rssi_values) if cluster.rssi_values else None,
        "rssi_max": max(cluster.rssi_values) if cluster.rssi_values else None,
        "rssi_avg": (sum(cluster.rssi_values) / len(cluster.rssi_values)) if cluster.rssi_values else None,
    }
    return summary


def _normalized_ts_to_epoch(value: Optional[str]) -> Optional[float]:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _to_float_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
