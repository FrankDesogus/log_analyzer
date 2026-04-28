from __future__ import annotations

from pathlib import Path
import json
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

    enriched_events = [enrich_canonical_event(event) for event in canonical_events]

    enriched_output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_output_path.write_text(
        json.dumps({"canonical_events": enriched_events}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    summary_payload = build_detection_summary(enriched_events)
    summary_output_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary_payload


def enrich_canonical_event(event: dict[str, Any]) -> dict[str, Any]:
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
        score = 35
        incident_type = "wifi_instability"
        reasons.append("wifi_disconnect_sequence: severità base low/medium")
        tags.add("wifi_disconnect")
        if disconnect_count >= 3:
            score += 15
            tags.add("repeated_disconnect")
            reasons.append(f"disconnect_count elevato ({disconnect_count})")
        if raw_event_count >= 10:
            score += 15
            tags.add("high_event_volume")
            reasons.append(f"raw_event_count >= 10 ({raw_event_count})")
        if is_likely_flapping(event_copy):
            tags.add("possibile_client_flapping")
            score += 10
            reasons.append("burst ravvicinato di disconnessioni rilevato")

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
