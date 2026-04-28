from __future__ import annotations

from pathlib import Path
import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from detection.severity import (
    clamp_score,
    confidence_from_reason_count,
    level_from_score,
    to_float,
    to_int,
)
from detection.summary import build_detection_summary


def run_detection_layer(
    canonical_input_path: Path,
    enriched_output_path: Path,
    summary_output_path: Path,
) -> dict[str, Any]:
    if not canonical_input_path.exists():
        raise FileNotFoundError(
            f"File canonical events non trovato: {canonical_input_path}. "
            "Esegui prima il parser/canonicalizer per generare canonical_events.json."
        )

    payload = json.loads(canonical_input_path.read_text(encoding="utf-8"))
    canonical_events = payload.get("canonical_events") if isinstance(payload, dict) else None
    if not isinstance(canonical_events, list):
        raise ValueError(
            f"Formato canonical events non valido in {canonical_input_path}: campo 'canonical_events' mancante o non-lista."
        )

    disconnect_context = build_disconnect_context(canonical_events)
    enriched_events = [enrich_canonical_event(event, disconnect_context=disconnect_context) for event in canonical_events]

    enriched_output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_output_path.write_text(
        json.dumps({"canonical_events": enriched_events}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    summary_payload = build_detection_summary(enriched_events)
    summary_output_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    diagnostics_output_path = summary_output_path.parent / "disconnect_sequence_diagnostics.json"
    diagnostics_payload = build_disconnect_sequence_diagnostics_payload(enriched_events)
    diagnostics_output_path.write_text(
        json.dumps(diagnostics_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return summary_payload


def enrich_canonical_event(
    event: dict[str, Any],
    disconnect_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event_copy = dict(event)
    canonical_type = str(event_copy.get("canonical_event_type") or "")
    sequence_summary = event_copy.get("sequence_summary") if isinstance(event_copy.get("sequence_summary"), dict) else {}

    raw_event_count = to_int(event_copy.get("raw_event_count"), 0)
    disconnect_count = to_int(sequence_summary.get("disconnect_count"), 0)
    rssi_avg = to_float(sequence_summary.get("rssi_avg"))
    event_types_seen = {str(x) for x in event_copy.get("event_types_seen", []) if x}

    reasons: list[str] = []
    tags: set[str] = set()
    incident_type = "informational"

    score = 15

    if canonical_type == "wifi_auth_sequence":
        score = 25
        incident_type = "wifi_instability"
        reasons.append("wifi_auth_sequence: severità base low")
        tags.add("wifi_auth")
        if rssi_avg is not None and rssi_avg <= -85:
            score += 20
            tags.add("poor_rssi")
            reasons.append(f"RSSI medio molto basso ({rssi_avg:.1f} dBm)")
        if raw_event_count >= 6:
            score += 10
            tags.add("noisy_sequence")
            reasons.append(f"raw_event_count elevato ({raw_event_count})")

    elif canonical_type == "wifi_auth_disconnect_sequence":
        score = 50
        incident_type = "wifi_instability"
        reasons.append("wifi_auth_disconnect_sequence: severità base medium")
        tags.update({"wifi_auth", "wifi_disconnect"})
        if disconnect_count >= 2:
            score += 15
            tags.add("repeated_disconnect")
            reasons.append(f"disconnect_count >= 2 ({disconnect_count})")
        if raw_event_count >= 8:
            score += 10
            tags.add("high_event_volume")
            reasons.append(f"raw_event_count >= 8 ({raw_event_count})")
        if rssi_avg is not None and rssi_avg <= -85:
            score += 15
            tags.add("poor_rssi")
            reasons.append(f"RSSI medio <= -85 ({rssi_avg:.1f} dBm)")

    elif canonical_type == "wifi_disconnect_sequence":
        disconnect_diagnostic = classify_disconnect_sequence(
            event_copy,
            disconnect_context=disconnect_context or {},
        )
        tags.update({"wifi_disconnect", *disconnect_diagnostic.get("detection_tags", [])})
        reasons.append(
            f"disconnect diagnostic: {disconnect_diagnostic.get('disconnect_diagnostic_label', 'needs_manual_review')}"
        )
        reasons.append(str(disconnect_diagnostic.get("disconnect_diagnostic_reason", "")))
        incident_type = str(disconnect_diagnostic.get("incident_type") or "wifi_instability")
        score = int(disconnect_diagnostic.get("severity_score_hint") or 35)
        if disconnect_count >= 3:
            tags.add("repeated_disconnect")
            reasons.append(f"disconnect_count elevato ({disconnect_count})")
        if raw_event_count >= 10:
            tags.add("high_event_volume")
            reasons.append(f"raw_event_count >= 10 ({raw_event_count})")
        event_copy.update(disconnect_diagnostic)

    elif canonical_type == "wifi_security_sequence":
        score = 55
        incident_type = "wifi_security"
        tags.add("wifi_security")
        reasons.append("wifi_security_sequence: severità minima medium")
        security_hits = _security_event_hits(event_types_seen)
        if security_hits:
            score = max(score, 75)
            tags.add("explicit_security_signal")
            reasons.append(f"eventi security rilevati: {', '.join(sorted(security_hits))}")

    elif canonical_type in {"device_config_sequence", "device_management_sequence", "system_logging_sequence"}:
        score = 12
        incident_type = "device_config"
        tags.add("device_or_system")
        reasons.append("evento device/system: severità info/low di default")

    elif canonical_type.startswith("network_"):
        score = 25
        incident_type = "network_service_issue"
        tags.add("network_service")
        reasons.append("sequenza di rete non-wifi security: severità low")

    else:
        score = 18
        reasons.append("evento non classificato in regole dedicate: informational")

    severity_score = clamp_score(score)
    severity_level = level_from_score(severity_score)
    incident_candidate = severity_score >= 60 and canonical_type not in {
        "device_config_sequence",
        "device_management_sequence",
        "system_logging_sequence",
    }
    if incident_candidate:
        tags.add("incident_candidate")

    confidence_score = confidence_from_reason_count(len(reasons), bonus=0.05 if incident_candidate else 0.0)

    event_copy.update(
        {
            "severity_score": severity_score,
            "severity_level": severity_level,
            "confidence_score": confidence_score,
            "incident_candidate": incident_candidate,
            "incident_type": incident_type,
            "detection_tags": sorted(tags),
            "detection_reason": reasons,
        }
    )
    return event_copy


def is_likely_flapping(event: dict[str, Any]) -> bool:
    raw_event_count = to_int(event.get("raw_event_count"), 0)
    duration_ms = to_int(event.get("duration_ms"), 0)
    if raw_event_count < 4:
        return False
    if 0 < duration_ms <= 1500:
        return True

    line_numbers = event.get("raw_line_numbers")
    if isinstance(line_numbers, list) and len(line_numbers) >= 4:
        gaps = []
        for i in range(1, len(line_numbers)):
            prev = to_int(line_numbers[i - 1], -1)
            curr = to_int(line_numbers[i], -1)
            if prev >= 0 and curr >= 0:
                gaps.append(abs(curr - prev))
        if gaps and sum(gaps) / len(gaps) <= 4:
            return True
    return False


def classify_disconnect_sequence(
    canonical_event: dict[str, Any],
    disconnect_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sequence_summary = (
        canonical_event.get("sequence_summary") if isinstance(canonical_event.get("sequence_summary"), dict) else {}
    )
    raw_event_count = to_int(canonical_event.get("raw_event_count"), 0)
    disconnect_count = to_int(sequence_summary.get("disconnect_count"), 0)
    process_names_seen = {str(x) for x in canonical_event.get("process_names_seen", []) if x}
    sources_seen = {str(x) for x in canonical_event.get("sources_seen", []) if x}
    event_types_seen = {str(x) for x in canonical_event.get("event_types_seen", []) if x}
    client_mac = str(canonical_event.get("client_mac") or "unknown")
    source_ip = str(canonical_event.get("source_ip") or "unknown")
    radio = str(canonical_event.get("radio") or "unknown")
    duration_ms = to_int(canonical_event.get("duration_ms"), 0)
    timestamp_gap_seconds = to_float(canonical_event.get("timestamp_gap_seconds"))
    max_line_gap = to_int(canonical_event.get("max_line_gap"), 0)
    rssi_avg = to_float(sequence_summary.get("rssi_avg"))

    disconnect_only = bool(event_types_seen) and event_types_seen.issubset({"disconnect"})
    has_auth = bool({"auth_request", "auth_response"} & event_types_seen)
    has_hostapd_wevent = "hostapd" in process_names_seen and "wevent" in process_names_seen
    high_volume = raw_event_count >= 12 or disconnect_count >= 8

    tags: set[str] = {"disconnect_sequence"}
    if disconnect_only:
        tags.add("disconnect_only_sequence")
    if has_hostapd_wevent:
        tags.add("hostapd_wevent_duplicate")

    context = disconnect_context or {}
    client_stats = context.get("client_stats", {}).get(client_mac, {})
    client_disconnect_only_count = int(client_stats.get("disconnect_only_sequences", 0))
    client_min_gap_seconds = to_float(client_stats.get("min_gap_seconds"))
    client_sources = int(client_stats.get("unique_source_ips", 0))
    client_radios = int(client_stats.get("unique_radios", 0))

    noise_score = 0
    flapping_score = 0
    label = "needs_manual_review"
    reason = "Nessuna regola diagnostica forte soddisfatta."
    incident_type = "wifi_instability"
    severity_hint = 35

    if disconnect_only and has_hostapd_wevent and rssi_avg is None and not has_auth and high_volume:
        label = "probable_unifi_duplicate_noise"
        incident_type = "wifi_noise"
        severity_hint = 45
        noise_score = 85
        tags.update({"unifi_duplicate_disconnect", "hostapd_wevent_duplicate", "disconnect_only_sequence"})
        reason = (
            "Sequenza solo disconnect con hostapd+wevent, senza RSSI/auth, con alto volume: "
            "probabile duplicazione UniFi."
        )
    elif disconnect_only and client_disconnect_only_count >= 4 and (
        client_min_gap_seconds is None or client_min_gap_seconds <= 180.0
    ):
        label = "client_flapping"
        incident_type = "wifi_instability"
        flapping_score = min(100, 40 + client_disconnect_only_count * 10)
        severity_hint = 60 if flapping_score >= 80 else 50
        tags.update({"client_flapping", "repeated_disconnect_burst"})
        reason = (
            f"Client con molte sequenze disconnect-only ravvicinate "
            f"({client_disconnect_only_count} sequenze)."
        )
    elif disconnect_count >= 3 and raw_event_count >= 6 and duration_ms <= 5000:
        label = "client_disconnect_burst"
        incident_type = "wifi_instability"
        severity_hint = 55
        reason = "Burst di disconnect concentrato sulla stessa sequenza client."
    elif disconnect_count >= 3 and raw_event_count >= 10:
        label = "ap_radio_disconnect_burst"
        incident_type = "wifi_instability"
        severity_hint = 58
        reason = "Burst disconnect ampio, potenzialmente legato al lato AP/radio."

    if client_sources <= 1 or client_radios <= 1 or len(sources_seen) <= 1:
        tags.add("ap_radio_specific_issue")
    elif client_sources > 1 and client_radios > 1:
        tags.add("client_side_or_roaming_issue")

    if source_ip != "unknown":
        tags.add(f"source_ip:{source_ip}")
    if radio != "unknown":
        tags.add(f"radio:{radio}")

    if timestamp_gap_seconds is not None and timestamp_gap_seconds > 90:
        noise_score = max(0, noise_score - 20)
    if max_line_gap > 200:
        noise_score = max(0, noise_score - 15)

    return {
        "disconnect_diagnostic_label": label,
        "disconnect_diagnostic_reason": reason,
        "disconnect_noise_score": int(min(100, max(0, noise_score))),
        "disconnect_flapping_score": int(min(100, max(0, flapping_score))),
        "detection_tags": sorted(tags),
        "incident_type": incident_type,
        "severity_score_hint": severity_hint,
    }


def build_disconnect_context(canonical_events: list[dict[str, Any]]) -> dict[str, Any]:
    disconnect_events = [
        event for event in canonical_events if (event.get("canonical_event_type") or "") == "wifi_disconnect_sequence"
    ]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in disconnect_events:
        grouped[str(event.get("client_mac") or "unknown")].append(event)

    client_stats: dict[str, dict[str, Any]] = {}
    for client_mac, events in grouped.items():
        normalized_timestamps: list[float] = []
        for event in events:
            epoch = _normalized_ts_to_epoch(event.get("normalized_timestamp"))
            if epoch is not None:
                normalized_timestamps.append(epoch)
        normalized_timestamps.sort()
        gaps = [
            normalized_timestamps[index + 1] - normalized_timestamps[index]
            for index in range(len(normalized_timestamps) - 1)
        ]
        min_gap_seconds = min(gaps) if gaps else None
        disconnect_only_count = 0
        source_ips: set[str] = set()
        radios: set[str] = set()
        for event in events:
            event_types_seen = {str(x) for x in event.get("event_types_seen", []) if x}
            if event_types_seen and event_types_seen.issubset({"disconnect"}):
                disconnect_only_count += 1
            source_ips.add(str(event.get("source_ip") or "unknown"))
            radios.add(str(event.get("radio") or "unknown"))
        client_stats[client_mac] = {
            "disconnect_only_sequences": disconnect_only_count,
            "unique_source_ips": len(source_ips),
            "unique_radios": len(radios),
            "min_gap_seconds": min_gap_seconds,
        }
    return {"client_stats": client_stats}


def _normalized_ts_to_epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def build_disconnect_sequence_diagnostics_payload(enriched_events: list[dict[str, Any]]) -> dict[str, Any]:
    disconnect_sequences = [
        event for event in enriched_events if (event.get("canonical_event_type") or "") == "wifi_disconnect_sequence"
    ]
    suspicious = [event for event in disconnect_sequences if int(event.get("raw_event_count") or 0) > 15]
    label_counts = Counter(str(event.get("disconnect_diagnostic_label") or "needs_manual_review") for event in suspicious)
    top_clients = Counter(str(event.get("client_mac") or "unknown") for event in suspicious).most_common(10)
    top_source_ips = Counter(str(event.get("source_ip") or "unknown") for event in suspicious).most_common(10)
    top_radios = Counter(str(event.get("radio") or "unknown") for event in suspicious).most_common(10)

    samples_by_label: dict[str, list[dict[str, Any]]] = {}
    for event in suspicious:
        label = str(event.get("disconnect_diagnostic_label") or "needs_manual_review")
        bucket = samples_by_label.setdefault(label, [])
        if len(bucket) >= 3:
            continue
        bucket.append(
            {
                "canonical_event_id": event.get("canonical_event_id"),
                "client_mac": event.get("client_mac"),
                "source_ip": event.get("source_ip"),
                "radio": event.get("radio"),
                "raw_event_count": int(event.get("raw_event_count") or 0),
                "disconnect_diagnostic_reason": event.get("disconnect_diagnostic_reason"),
            }
        )

    return {
        "total_wifi_disconnect_sequences": len(disconnect_sequences),
        "suspicious_wifi_disconnect_sequences": len(suspicious),
        "disconnect_diagnostic_distribution": dict(label_counts),
        "disconnect_only_sequence_count": sum(
            1
            for event in suspicious
            if "disconnect_only_sequence" in set(event.get("detection_tags") or [])
        ),
        "probable_unifi_duplicate_noise_count": int(label_counts.get("probable_unifi_duplicate_noise", 0)),
        "client_flapping_count": int(label_counts.get("client_flapping", 0)),
        "ap_radio_disconnect_burst_count": int(label_counts.get("ap_radio_disconnect_burst", 0)),
        "needs_manual_review_count": int(label_counts.get("needs_manual_review", 0)),
        "top_disconnect_clients": [{"client_mac": value, "sequence_count": count} for value, count in top_clients],
        "top_disconnect_source_ips": [{"source_ip": value, "sequence_count": count} for value, count in top_source_ips],
        "top_disconnect_radios": [{"radio": value, "sequence_count": count} for value, count in top_radios],
        "samples_by_label": samples_by_label,
    }


def _security_event_hits(event_types_seen: set[str]) -> set[str]:
    rule_map = {
        "deauth_sent": "deauth",
        "wifi_key_delete": "key_delete",
        "auth_response": "auth_failure_or_response",
        "assoc_tracker_failure": "auth_failure",
        "station_delete": "station_delete",
        "cfg80211_station_delete": "cfg80211_station_delete",
    }
    hits = set()
    for event_type, label in rule_map.items():
        if event_type in event_types_seen:
            hits.add(label)
    return hits
