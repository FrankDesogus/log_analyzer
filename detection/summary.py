from __future__ import annotations

from collections import Counter
from typing import Any

from detection.severity import level_rank


def build_detection_summary(enriched_events: list[dict[str, Any]]) -> dict[str, Any]:
    severity_distribution = Counter(
        (event.get("severity_level") or "info") for event in enriched_events
    )
    incident_candidates = [event for event in enriched_events if bool(event.get("incident_candidate"))]

    top_incident_candidates = sorted(
        incident_candidates,
        key=lambda e: (
            int(e.get("severity_score") or 0),
            float(e.get("confidence_score") or 0.0),
        ),
        reverse=True,
    )[:10]

    top_clients = _aggregate_top_entities(enriched_events, field="client_mac")
    top_source_ips = _aggregate_top_entities(enriched_events, field="source_ip")

    event_type_risk_distribution = Counter(
        (event.get("canonical_event_type") or "unknown") for event in enriched_events
    )
    tag_distribution = Counter()
    for event in enriched_events:
        tags = event.get("detection_tags")
        if isinstance(tags, list):
            tag_distribution.update(str(tag) for tag in tags if tag)

    return {
        "total_enriched_events": len(enriched_events),
        "severity_distribution": dict(sorted(severity_distribution.items())),
        "incident_candidate_count": len(incident_candidates),
        "top_incident_candidates": [
            {
                "canonical_event_id": event.get("canonical_event_id"),
                "canonical_event_type": event.get("canonical_event_type"),
                "severity_score": event.get("severity_score"),
                "severity_level": event.get("severity_level"),
                "confidence_score": event.get("confidence_score"),
                "incident_type": event.get("incident_type"),
                "detection_tags": event.get("detection_tags", []),
            }
            for event in top_incident_candidates
        ],
        "top_clients_by_severity": top_clients,
        "top_source_ips_by_severity": top_source_ips,
        "event_type_risk_distribution": dict(sorted(event_type_risk_distribution.items())),
        "detection_tags_distribution": dict(tag_distribution.most_common()),
    }


def _aggregate_top_entities(enriched_events: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}

    for event in enriched_events:
        key = str(event.get(field) or "unknown")
        item = buckets.setdefault(
            key,
            {
                field: key,
                "event_count": 0,
                "max_severity_score": 0,
                "max_severity_level": "info",
                "incident_candidate_count": 0,
            },
        )
        score = int(event.get("severity_score") or 0)
        level = str(event.get("severity_level") or "info")

        item["event_count"] += 1
        item["max_severity_score"] = max(item["max_severity_score"], score)
        if level_rank(level) > level_rank(item["max_severity_level"]):
            item["max_severity_level"] = level
        if bool(event.get("incident_candidate")):
            item["incident_candidate_count"] += 1

    return sorted(
        buckets.values(),
        key=lambda entry: (
            entry["max_severity_score"],
            entry["incident_candidate_count"],
            entry["event_count"],
        ),
        reverse=True,
    )[:10]
