from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from detection.severity import clamp_score, level_from_score, to_float, to_int

INCIDENT_GROUP_WINDOW_SECONDS = 300.0


def run_incident_builder(
    enriched_input_path: Path,
    incidents_output_path: Path,
    summary_output_path: Path,
    analyst_summary_output_path: Path | None = None,
    window_seconds: float = INCIDENT_GROUP_WINDOW_SECONDS,
) -> dict[str, Any]:
    if not enriched_input_path.exists():
        raise FileNotFoundError(
            f"File enriched events non trovato: {enriched_input_path}. "
            "Esegui prima il detection/enrichment layer per generare enriched_canonical_events.json."
        )

    payload = json.loads(enriched_input_path.read_text(encoding="utf-8"))
    enriched_events = payload.get("canonical_events") if isinstance(payload, dict) else None
    if not isinstance(enriched_events, list):
        raise ValueError(
            f"Formato enriched events non valido in {enriched_input_path}: campo 'canonical_events' mancante o non-lista."
        )

    incidents, incident_metrics = build_incidents(enriched_events, window_seconds=window_seconds)
    summary = build_incident_summary(incidents, incident_metrics)
    analyst_summary = build_analyst_summary(incidents, incident_metrics)

    incidents_output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_output_path.parent.mkdir(parents=True, exist_ok=True)
    if analyst_summary_output_path is not None:
        analyst_summary_output_path.parent.mkdir(parents=True, exist_ok=True)
    incidents_output_path.write_text(json.dumps({"incidents": incidents}, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if analyst_summary_output_path is not None:
        analyst_summary_output_path.write_text(json.dumps(analyst_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def build_incidents(enriched_events: list[dict[str, Any]], window_seconds: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    filtered_events: list[dict[str, Any]] = []
    suppression_metrics = Counter()
    for event in enriched_events:
        include, normalized_incident_type, suppression_label = _should_include_in_incidents(event)
        if not include:
            suppression_metrics.update([suppression_label or "suppressed_single_events"])
            continue
        event_copy = dict(event)
        event_copy["_incident_type"] = normalized_incident_type
        event_copy["_event_time_seconds"] = _event_time_seconds(event_copy)
        filtered_events.append(event_copy)

    filtered_events.sort(
        key=lambda event: (
            event.get("_event_time_seconds") if event.get("_event_time_seconds") is not None else float("inf"),
            str(event.get("canonical_event_id") or ""),
        )
    )

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in filtered_events:
        incident_type = str(event.get("_incident_type") or "informational")
        client_key = str(event.get("client_mac") or "unknown")
        source_group_key = _source_group_key(event)
        key = (incident_type, client_key, source_group_key)

        candidate_incidents = grouped[key]
        if not candidate_incidents:
            candidate_incidents.append(_new_incident_state(event))
            continue

        last_incident = candidate_incidents[-1]
        event_time = to_float(event.get("_event_time_seconds"))
        last_time = to_float(last_incident.get("last_seen_seconds"))
        if event_time is not None and last_time is not None and event_time - last_time <= window_seconds:
            _append_event_to_incident(last_incident, event)
        else:
            candidate_incidents.append(_new_incident_state(event))

    incidents: list[dict[str, Any]] = []
    seq = 1
    for key_incidents in grouped.values():
        for state in key_incidents:
            incidents.append(_finalize_incident(state, seq))
            seq += 1

    incidents.sort(
        key=lambda item: (
            int(item.get("severity_score") or 0),
            float(item.get("confidence_score") or 0.0),
            int(item.get("canonical_event_count") or 0),
            str(item.get("first_seen") or ""),
        ),
        reverse=True,
    )
    incident_metrics = _build_incident_metrics(incidents, suppression_metrics)
    return incidents, incident_metrics


def _should_include_in_incidents(event: dict[str, Any]) -> tuple[bool, str, str | None]:
    incident_type = str(event.get("incident_type") or "informational")
    severity_score = to_int(event.get("severity_score"), 0)
    incident_candidate = bool(event.get("incident_candidate"))
    tags = {str(tag) for tag in event.get("detection_tags", []) if tag}
    disconnect_label = str(event.get("disconnect_diagnostic_label") or "")

    if "client_flapping" in tags or disconnect_label == "client_flapping":
        if severity_score >= 80 or "wifi_security" in tags:
            return True, "client_flapping", None
        return False, "client_flapping", "suppressed_single_events"

    if disconnect_label == "probable_unifi_duplicate_noise" or incident_type == "wifi_noise":
        if severity_score >= 80 or "wifi_security" in tags:
            return True, "wifi_noise", None
        return False, "wifi_noise", "noise_unifi"

    if incident_type == "wifi_security":
        return True, "wifi_security", None

    if incident_type == "wifi_instability":
        include = severity_score >= 50 or incident_candidate
        return include, "wifi_instability", "low_priority_patterns" if not include else None

    if incident_type in {"informational", "device_config", "device_management"}:
        include = severity_score >= 50
        return include, incident_type, "low_priority_patterns" if not include else None

    include = severity_score >= 50
    return include, incident_type, "low_priority_patterns" if not include else None


def _event_time_seconds(event: dict[str, Any]) -> float | None:
    first_internal = to_float(event.get("first_internal_event_ts"))
    if first_internal is not None:
        return first_internal
    return to_float(event.get("last_internal_event_ts"))


def _source_group_key(event: dict[str, Any]) -> str:
    source_ip = str(event.get("source_ip") or "unknown")
    parts = source_ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return source_ip


def _new_incident_state(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("canonical_event_type") or "unknown")
    tags = [str(tag) for tag in event.get("detection_tags", []) if tag]
    reasons = [str(reason) for reason in event.get("detection_reason", []) if reason]
    source_ip = str(event.get("source_ip") or "unknown")
    client_mac = str(event.get("client_mac") or "unknown")
    radio = str(event.get("radio") or "unknown")
    ap_mac = str(event.get("ap_mac") or "unknown")

    start_ts = to_float(event.get("_event_time_seconds"))
    end_ts = to_float(event.get("last_internal_event_ts"), start_ts)

    return {
        "incident_type": str(event.get("_incident_type") or "informational"),
        "client_mac": client_mac,
        "first_seen": str(event.get("normalized_timestamp") or ""),
        "last_seen": str(event.get("normalized_timestamp") or ""),
        "first_seen_seconds": start_ts,
        "last_seen_seconds": end_ts,
        "severity_scores": [to_int(event.get("severity_score"), 0)],
        "confidence_scores": [to_float(event.get("confidence_score"), 0.0) or 0.0],
        "source_ips": {source_ip},
        "radios": {radio} if radio != "unknown" else set(),
        "ap_macs": {ap_mac} if ap_mac != "unknown" else set(),
        "canonical_event_ids": [str(event.get("canonical_event_id") or "unknown")],
        "event_type_distribution": Counter([event_type]),
        "detection_tags": Counter(tags),
        "detection_reasons": Counter(reasons),
    }


def _append_event_to_incident(incident: dict[str, Any], event: dict[str, Any]) -> None:
    incident["severity_scores"].append(to_int(event.get("severity_score"), 0))
    incident["confidence_scores"].append(to_float(event.get("confidence_score"), 0.0) or 0.0)

    source_ip = str(event.get("source_ip") or "unknown")
    incident["source_ips"].add(source_ip)

    radio = str(event.get("radio") or "unknown")
    if radio != "unknown":
        incident["radios"].add(radio)

    ap_mac = str(event.get("ap_mac") or "unknown")
    if ap_mac != "unknown":
        incident["ap_macs"].add(ap_mac)

    event_id = str(event.get("canonical_event_id") or "unknown")
    incident["canonical_event_ids"].append(event_id)

    event_type = str(event.get("canonical_event_type") or "unknown")
    incident["event_type_distribution"].update([event_type])

    tags = [str(tag) for tag in event.get("detection_tags", []) if tag]
    incident["detection_tags"].update(tags)

    reasons = [str(reason) for reason in event.get("detection_reason", []) if reason]
    incident["detection_reasons"].update(reasons)

    normalized_timestamp = str(event.get("normalized_timestamp") or "")
    if normalized_timestamp:
        if not incident["first_seen"] or normalized_timestamp < incident["first_seen"]:
            incident["first_seen"] = normalized_timestamp
        if not incident["last_seen"] or normalized_timestamp > incident["last_seen"]:
            incident["last_seen"] = normalized_timestamp

    event_start = to_float(event.get("_event_time_seconds"))
    event_end = to_float(event.get("last_internal_event_ts"), event_start)

    current_start = to_float(incident.get("first_seen_seconds"))
    current_end = to_float(incident.get("last_seen_seconds"))
    if event_start is not None and (current_start is None or event_start < current_start):
        incident["first_seen_seconds"] = event_start
    if event_end is not None and (current_end is None or event_end > current_end):
        incident["last_seen_seconds"] = event_end


def _finalize_incident(incident: dict[str, Any], sequence_number: int) -> dict[str, Any]:
    severity_scores = incident.get("severity_scores", [])
    max_severity = max(severity_scores) if severity_scores else 0
    event_count = len(incident.get("canonical_event_ids", []))
    volume_boost = min(10, max(0, event_count - 1) * 2)
    final_score = clamp_score(max_severity + volume_boost)

    incident_type = str(incident.get("incident_type") or "informational")
    if incident_type == "wifi_noise":
        final_score = min(final_score, 79)

    severity_level = level_from_score(final_score)
    confidence_scores = incident.get("confidence_scores", [])
    confidence_score = round(sum(confidence_scores) / len(confidence_scores), 2) if confidence_scores else 0.0

    source_ips = sorted(incident.get("source_ips", set()))
    radios = sorted(incident.get("radios", set()))
    ap_macs = sorted(incident.get("ap_macs", set()))

    canonical_event_ids = sorted(incident.get("canonical_event_ids", []))
    event_type_distribution = dict(sorted(incident.get("event_type_distribution", Counter()).items()))

    tags_counter = incident.get("detection_tags", Counter())
    detection_tags = [tag for tag, _ in tags_counter.most_common()]

    reason_counter = incident.get("detection_reasons", Counter())
    primary_reason = reason_counter.most_common(1)[0][0] if reason_counter else "Aggregazione eventi correlati"

    first_seen_seconds = to_float(incident.get("first_seen_seconds"))
    last_seen_seconds = to_float(incident.get("last_seen_seconds"), first_seen_seconds)
    duration_seconds = round(max(0.0, (last_seen_seconds or 0.0) - (first_seen_seconds or 0.0)), 3)

    analyst_priority = _analyst_priority(incident_type, final_score, event_count, source_ips, radios, ap_macs, detection_tags, confidence_score, severity_level)
    operational_impact_score = _operational_impact_score({
        "severity_score": final_score,
        "analyst_priority": analyst_priority,
        "canonical_event_count": event_count,
        "duration_seconds": duration_seconds,
        "source_ips": source_ips,
        "radios": radios,
        "ap_macs": ap_macs,
        "detection_tags": detection_tags,
    })
    why_it_matters = _why_it_matters(incident_type, analyst_priority, event_count)
    recommended_action = _recommended_action(incident_type)
    evidence_summary = (
        f"{event_count} eventi canonici correlati per client {incident.get('client_mac')} "
        f"su {len(source_ips)} source IP, tag principali: {', '.join(detection_tags[:3]) or 'n/a'}."
    )

    return {
        "incident_id": f"INC-{sequence_number:05d}",
        "incident_type": incident_type,
        "severity_score": final_score,
        "severity_level": severity_level,
        "analyst_priority": analyst_priority,
        "operational_impact_score": operational_impact_score,
        "confidence_score": confidence_score,
        "status": "open",
        "first_seen": incident.get("first_seen") or None,
        "last_seen": incident.get("last_seen") or None,
        "duration_seconds": duration_seconds,
        "client_mac": incident.get("client_mac"),
        "source_ips": source_ips,
        "radios": radios,
        "ap_macs": ap_macs,
        "canonical_event_count": event_count,
        "canonical_event_ids": canonical_event_ids,
        "event_type_distribution": event_type_distribution,
        "detection_tags": detection_tags,
        "why_it_matters": why_it_matters,
        "primary_detection_reason": primary_reason,
        "evidence_summary": evidence_summary,
        "recommended_action": recommended_action,
    }


def _recommended_action(incident_type: str) -> str:
    if incident_type == "wifi_instability":
        return "Verificare RSSI, roaming, copertura radio, distanza client/AP e possibili interferenze."
    if incident_type == "wifi_noise":
        return "Probabile rumore/duplicazione log UniFi: verificare solo se volume anomalo o persistente."
    if incident_type == "client_flapping":
        return "Verificare il dispositivo client, roaming aggressivo, driver Wi-Fi, alimentazione e posizione."
    if incident_type == "wifi_security":
        return "Verificare deauth, EAPOL, key deletion e possibili problemi di autenticazione/sicurezza."
    return "Verificare il contesto operativo e correlare con altri segnali SIEM prima di intervenire."


def build_incident_summary(incidents: list[dict[str, Any]], incident_metrics: dict[str, Any]) -> dict[str, Any]:
    severity_distribution = Counter(str(item.get("severity_level") or "info") for item in incidents)
    incident_type_distribution = Counter(str(item.get("incident_type") or "informational") for item in incidents)

    top_clients = Counter(str(item.get("client_mac") or "unknown") for item in incidents)

    source_counter = Counter()
    tag_counter = Counter()
    for item in incidents:
        source_counter.update(str(ip) for ip in item.get("source_ips", []) if ip)
        tag_counter.update(str(tag) for tag in item.get("detection_tags", []) if tag)

    top_by_operational_impact = sorted(
        incidents,
        key=lambda item: (
            int(item.get("operational_impact_score") or 0),
            _priority_rank(str(item.get("analyst_priority") or "P3")),
            int(item.get("severity_score") or 0),
            int(item.get("canonical_event_count") or 0),
            float(item.get("confidence_score") or 0.0),
        ),
        reverse=True,
    )[:10]

    incident_counts = [int(item.get("canonical_event_count") or 0) for item in incidents]
    average_events_per_incident = round(sum(incident_counts) / len(incident_counts), 2) if incident_counts else 0.0
    max_events_per_incident = max(incident_counts) if incident_counts else 0

    first_seen_values = [str(item.get("first_seen")) for item in incidents if item.get("first_seen")]
    last_seen_values = [str(item.get("last_seen")) for item in incidents if item.get("last_seen")]

    priority_distribution = Counter(str(item.get("analyst_priority") or "P3") for item in incidents)
    true_incidents = [item for item in incidents if item.get("analyst_priority") != "noise"]
    top_problematic_clients = _build_problematic_clients(true_incidents)
    top_involved_source_ips = _top_nested_entity(true_incidents, "source_ips", "source_ip")
    top_involved_radios = _top_nested_entity(true_incidents, "radios", "radio")
    top_involved_ap_macs = _top_nested_entity(true_incidents, "ap_macs", "ap_mac")

    return {
        "total_incidents": len(incidents),
        "total_true_incidents": len(true_incidents),
        "total_noise_incidents": len(incidents) - len(true_incidents),
        "suppressed_single_event_count": incident_metrics.get("suppressed_single_events", 0),
        "severity_distribution": dict(sorted(severity_distribution.items())),
        "incident_type_distribution": dict(sorted(incident_type_distribution.items())),
        "analyst_priority_distribution": dict(sorted(priority_distribution.items())),
        "top_clients": [{"client_mac": client, "incident_count": count} for client, count in top_clients.most_common(10)],
        "top_source_ips": [{"source_ip": ip, "incident_count": count} for ip, count in source_counter.most_common(10)],
        "top_detection_tags": [{"tag": tag, "count": count} for tag, count in tag_counter.most_common(10)],
        "top_incidents_by_severity": [
            {
                "incident_id": item.get("incident_id"),
                "incident_type": item.get("incident_type"),
                "severity_score": item.get("severity_score"),
                "severity_level": item.get("severity_level"),
                "operational_impact_score": item.get("operational_impact_score"),
                "canonical_event_count": item.get("canonical_event_count"),
                "client_mac": item.get("client_mac"),
            }
            for item in top_by_operational_impact
        ],
        "incident_time_range": {
            "first_seen": min(first_seen_values) if first_seen_values else None,
            "last_seen": max(last_seen_values) if last_seen_values else None,
        },
        "average_events_per_incident": average_events_per_incident,
        "max_events_per_incident": max_events_per_incident,
        "top_true_incidents": [
            {
                "incident_id": item.get("incident_id"),
                "incident_type": item.get("incident_type"),
                "analyst_priority": item.get("analyst_priority"),
                "severity_score": item.get("severity_score"),
                "operational_impact_score": item.get("operational_impact_score"),
                "canonical_event_count": item.get("canonical_event_count"),
            }
            for item in top_by_operational_impact
            if item.get("analyst_priority") != "noise"
        ],
        "top_problematic_clients": top_problematic_clients,
        "top_involved_source_ips": top_involved_source_ips,
        "top_involved_radios": top_involved_radios,
        "top_involved_ap_macs": top_involved_ap_macs,
        "total_suppressed_or_low_priority_events": (
            incident_metrics.get("suppressed_single_events", 0)
            + incident_metrics.get("low_priority_patterns", 0)
            + incident_metrics.get("noise_unifi", 0)
        ),
        "noise_or_suppressed_breakdown": {
            "suppressed_single_event_count": incident_metrics.get("suppressed_single_events", 0),
            "low_priority_patterns": incident_metrics.get("low_priority_patterns", 0),
            "noise_unifi_events": incident_metrics.get("noise_unifi", 0),
        },
        "summary_note": "Eventi sorgente non eliminati: enriched_canonical_events.json resta completo; incidenti finali sono vista analyst/SIEM con noise/suppression separati.",
        "suppressed_events_breakdown": incident_metrics,
    }


def _priority_rank(priority: str) -> int:
    return {"noise": 0, "P3": 1, "P2": 2, "P1": 3}.get(priority, 1)


def _operational_impact_score(incident: dict[str, Any]) -> int:
    """Conservative SOC ranking score, capped to 120."""
    base_score = to_int(incident.get("severity_score"), 0)
    priority_weight = {"noise": 0, "P3": 8, "P2": 14, "P1": 20}.get(str(incident.get("analyst_priority") or "P3"), 8)
    event_count = to_int(incident.get("canonical_event_count"), 0)
    duration_seconds = to_float(incident.get("duration_seconds"), 0.0) or 0.0
    source_ip_count = len(incident.get("source_ips", []))
    radio_count = len(incident.get("radios", []))
    ap_count = len(incident.get("ap_macs", []))
    tags = set(str(tag) for tag in incident.get("detection_tags", []) if tag)

    volume_weight = min(24, round(event_count * 0.12))
    duration_weight = min(12, round(duration_seconds / 300))
    scope_weight = min(18, (max(0, source_ip_count - 1) * 4) + (max(0, radio_count - 1) * 3) + (max(0, ap_count - 1) * 3))
    tag_weight = (
        (4 if "incident_candidate" in tags else 0)
        + (5 if "high_event_volume" in tags else 0)
        + (5 if "repeated_disconnect" in tags else 0)
        + (4 if "poor_rssi" in tags else 0)
        + (6 if "wifi_security" in tags else 0)
    )
    return min(120, base_score + priority_weight + volume_weight + duration_weight + scope_weight + tag_weight)


def _analyst_priority(
    incident_type: str,
    final_score: int,
    event_count: int,
    source_ips: list[str],
    radios: list[str],
    ap_macs: list[str],
    detection_tags: list[str],
    confidence_score: float,
    severity_level: str,
) -> str:
    tags = set(detection_tags)
    multi_scope = sum([len(source_ips) > 1, len(radios) > 1, len(ap_macs) > 1])

    if incident_type == "wifi_noise":
        return "noise"

    if severity_level == "critical" or final_score >= 85:
        return "P1"

    if incident_type == "wifi_security":
        if final_score >= 85 and confidence_score >= 0.8:
            return "P1"
        if event_count >= 3 or final_score >= 65 or confidence_score >= 0.7:
            return "P2"
        return "P3"

    if incident_type == "wifi_instability":
        if event_count >= 6 or (event_count >= 4 and multi_scope >= 2):
            return "P1"
        if final_score >= 70 or event_count >= 3 or multi_scope >= 1:
            return "P2"
        return "P3"

    if {"poor_rssi", "repeated_disconnect", "high_event_volume"}.intersection(tags):
        if final_score >= 80 and event_count >= 4:
            return "P1"
        if final_score >= 60 or event_count >= 3:
            return "P2"

    if event_count >= 4 and multi_scope >= 1:
        return "P2"
    if final_score >= 60 or event_count >= 2:
        return "P3"
    return "noise"


def _why_it_matters(incident_type: str, analyst_priority: str, event_count: int) -> str:
    if analyst_priority == "noise":
        return "Segnale classificato come rumore UniFi non azionabile; mantenuto per contabilità SIEM."
    return f"Incidente {incident_type} con {event_count} eventi correlati, priorità {analyst_priority} per investigazione operativa."


def _build_incident_metrics(incidents: list[dict[str, Any]], suppression_metrics: Counter[str]) -> dict[str, Any]:
    metrics = Counter(suppression_metrics)
    for incident in incidents:
        priority = str(incident.get("analyst_priority") or "P3")
        if priority == "noise":
            metrics.update(["noise_unifi_incidents"])
        elif priority == "P3":
            metrics.update(["low_priority_incidents"])
        else:
            metrics.update(["true_incidents"])
        if str(incident.get("incident_type") or "") == "wifi_security":
            metrics.update(["security_findings"])
    return dict(metrics)


def _top_entity_from_incidents(incidents: list[dict[str, Any]], field: str, output_field: str) -> list[dict[str, Any]]:
    counter = Counter(str(item.get(field) or "unknown") for item in incidents)
    return [{output_field: key, "count": value} for key, value in counter.most_common(10)]


def _top_nested_entity(incidents: list[dict[str, Any]], field: str, output_field: str) -> list[dict[str, Any]]:
    counter = Counter()
    for item in incidents:
        counter.update(str(val) for val in item.get(field, []) if val)
    return [{output_field: key, "count": value} for key, value in counter.most_common(10)]


def build_analyst_summary(incidents: list[dict[str, Any]], incident_metrics: dict[str, Any]) -> dict[str, Any]:
    true_incidents = sorted(
        [item for item in incidents if item.get("analyst_priority") in {"P1", "P2", "P3"}],
        key=lambda item: (
            int(item.get("operational_impact_score") or 0),
            _priority_rank(str(item.get("analyst_priority") or "P3")),
            int(item.get("canonical_event_count") or 0),
        ),
        reverse=True,
    )
    security_findings = [item for item in true_incidents if item.get("incident_type") == "wifi_security"]
    compact_incidents = []
    for item in true_incidents[:20]:
        compact_incidents.append(
            {
                "incident_id": item.get("incident_id"),
                "incident_type": item.get("incident_type"),
                "severity_score": item.get("severity_score"),
                "severity_level": item.get("severity_level"),
                "analyst_priority": item.get("analyst_priority"),
                "operational_impact_score": item.get("operational_impact_score"),
                "confidence_score": item.get("confidence_score"),
                "client_mac": item.get("client_mac"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "duration_seconds": item.get("duration_seconds"),
                "source_ips": item.get("source_ips", []),
                "radios": item.get("radios", []),
                "ap_macs": item.get("ap_macs", []),
                "canonical_event_count": item.get("canonical_event_count"),
                "sample_canonical_event_ids": item.get("canonical_event_ids", [])[:10],
                "detection_tags": item.get("detection_tags", [])[:5],
                "why_it_matters": item.get("why_it_matters"),
                "evidence_summary": item.get("evidence_summary"),
                "recommended_action": item.get("recommended_action"),
            }
        )

    return {
        "executive_summary": (
            f"{len(true_incidents)} incidenti reali da revisionare ordinati per impatto operativo; "
            "rumore/soppressioni classificati nel reporting senza perdita dei dati enriched."
        ),
        "true_incidents_to_review": compact_incidents,
        "what_to_investigate_first": _build_investigation_focus(true_incidents),
        "problematic_clients": _build_problematic_clients(true_incidents),
        "involved_source_ips": _top_nested_entity(true_incidents, "source_ips", "source_ip"),
        "involved_radios": _top_nested_entity(true_incidents, "radios", "radio"),
        "involved_ap_macs": _top_nested_entity(true_incidents, "ap_macs", "ap_mac"),
        "unifi_noise_summary": {
            "noise_unifi_events": incident_metrics.get("noise_unifi", 0),
            "noise_unifi_incidents": incident_metrics.get("noise_unifi_incidents", 0),
            "details": "Eventi classificati come rumore UniFi/duplicati hostapd-wevent, mantenuti in enriched_canonical_events.json per audit/forensics.",
        },
        "suppressed_events_summary": {
            "suppressed_single_events": incident_metrics.get("suppressed_single_events", 0),
            "low_priority_patterns": incident_metrics.get("low_priority_patterns", 0),
            "details": "Soppressione applicata solo nel reporting incident; nessun canonical event rimosso dai dataset sorgente o da OpenSearch.",
        },
        "recommended_operational_checks": [
            "Verificare client con flapping persistente su più radio/AP.",
            "Controllare AP/radio con disconnessioni ripetute e poor RSSI.",
            "Revisionare wifi_security medium/high in base a confidenza e volume eventi, non solo per presenza del tag.",
        ],
        "siem_readiness_notes": [
            "Nessun evento enriched rimosso: la soppressione è solo nel layer incident/reporting.",
            "Eventi soppressi e noise restano disponibili per analisi forense e pipeline OpenSearch.",
        ],
        "quality_guardrails": {
            "security_findings": len(security_findings),
            "true_incident_count": len(true_incidents),
            "suppression_metrics": incident_metrics,
        },
    }


def _build_investigation_focus(true_incidents: list[dict[str, Any]]) -> dict[str, Any]:
    if not true_incidents:
        return {"note": "Nessun true incident disponibile per prioritizzazione operativa."}
    top = true_incidents[0]
    return {
        "incident_id": top.get("incident_id"),
        "client_mac": top.get("client_mac"),
        "why_first": (
            f"Incident {top.get('incident_id')} prioritario per impact score {top.get('operational_impact_score')}, "
            f"priorità {top.get('analyst_priority')} e volume {top.get('canonical_event_count')}."
        ),
        "involved_entities": {
            "source_ips": top.get("source_ips", []),
            "radios": top.get("radios", []),
            "ap_macs": top.get("ap_macs", []),
        },
        "priority_evidence": {
            "severity_score": top.get("severity_score"),
            "duration_seconds": top.get("duration_seconds"),
            "detection_tags": top.get("detection_tags", [])[:6],
        },
        "operational_checks": [
            "Verificare AP/radio e qualità RF per il client prioritario.",
            "Correlare source IP coinvolti con eventuali anomalie di rete locale.",
            "Validare se i tag wifi_security/repeated_disconnect indicano rischio operativo o security.",
        ],
    }


def _build_problematic_clients(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for item in incidents:
        client = str(item.get("client_mac") or "unknown")
        bucket = buckets.setdefault(client, {
            "client_mac": client,
            "incident_count": 0,
            "total_canonical_event_count": 0,
            "max_severity_score": 0,
            "max_severity_level": "info",
            "highest_analyst_priority": "P3",
            "incident_types": set(),
            "source_ips": set(),
            "radios": set(),
            "ap_macs": set(),
            "key_detection_tags": Counter(),
            "_signals": set(),
        })
        bucket["incident_count"] += 1
        sev = int(item.get("severity_score") or 0)
        if sev > bucket["max_severity_score"]:
            bucket["max_severity_score"] = sev
            bucket["max_severity_level"] = str(item.get("severity_level") or "info")
        if _priority_rank(str(item.get("analyst_priority") or "P3")) > _priority_rank(bucket["highest_analyst_priority"]):
            bucket["highest_analyst_priority"] = str(item.get("analyst_priority") or "P3")
        bucket["total_canonical_event_count"] += int(item.get("canonical_event_count") or 0)
        bucket["incident_types"].add(str(item.get("incident_type") or "informational"))
        bucket["source_ips"].update(str(x) for x in item.get("source_ips", []) if x)
        bucket["radios"].update(str(x) for x in item.get("radios", []) if x)
        bucket["ap_macs"].update(str(x) for x in item.get("ap_macs", []) if x)
        tags = [str(t) for t in item.get("detection_tags", []) if t]
        bucket["key_detection_tags"].update(tags)
        for marker in ("poor_rssi", "repeated_disconnect", "high_event_volume", "wifi_security"):
            if marker in tags:
                bucket["_signals"].add(marker)

    output = []
    for bucket in buckets.values():
        output.append({
            "client_mac": bucket["client_mac"],
            "incident_count": bucket["incident_count"],
            "total_canonical_event_count": bucket["total_canonical_event_count"],
            "max_severity_score": bucket["max_severity_score"],
            "max_severity_level": bucket["max_severity_level"],
            "highest_analyst_priority": bucket["highest_analyst_priority"],
            "incident_types": sorted(bucket["incident_types"]),
            "source_ips": sorted(bucket["source_ips"]),
            "radios": sorted(bucket["radios"]),
            "ap_macs": sorted(bucket["ap_macs"]),
            "key_detection_tags": [tag for tag, _ in bucket["key_detection_tags"].most_common(6)],
            "operational_impact_score": _operational_impact_score({
                "severity_score": bucket["max_severity_score"],
                "analyst_priority": bucket["highest_analyst_priority"],
                "canonical_event_count": bucket["total_canonical_event_count"],
                "duration_seconds": 0.0,
                "source_ips": sorted(bucket["source_ips"]),
                "radios": sorted(bucket["radios"]),
                "ap_macs": sorted(bucket["ap_macs"]),
                "detection_tags": [tag for tag, _ in bucket["key_detection_tags"].most_common(6)],
            }),
            "recommended_action": "Prioritizzare troubleshooting RF/security sul client e correlare AP/radio coinvolti.",
            "_signal_count": len(bucket["_signals"]),
        })
    output.sort(key=lambda x: (
        x["operational_impact_score"],
        _priority_rank(x["highest_analyst_priority"]),
        x["total_canonical_event_count"],
        x["max_severity_score"],
        len(x["source_ips"]),
        len(x["radios"]),
        len(x["ap_macs"]),
        x["_signal_count"],
    ), reverse=True)
    for item in output:
        item.pop("_signal_count", None)
    return output[:10]
