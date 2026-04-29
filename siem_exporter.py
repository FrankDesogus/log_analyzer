import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _pick_timestamp(doc: dict[str, Any], *candidates: str) -> str:
    for key in candidates:
        value = doc.get(key)
        if value:
            return value
    return datetime.now(timezone.utc).isoformat()


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_docs(payload: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        value = payload.get(key)
        if isinstance(value, list):
            return [d for d in value if isinstance(d, dict)]
    if isinstance(payload, list):
        return [d for d in payload if isinstance(d, dict)]
    return []


def _write_bulk(path: Path, index_name: str, docs: list[dict[str, Any]], id_field: str, fallback_id_prefix: str) -> int:
    lines: list[str] = []
    for i, doc in enumerate(docs, start=1):
        doc_id = doc.get(id_field) or f"{fallback_id_prefix}-{i:06d}"
        action = {"index": {"_index": index_name, "_id": str(doc_id)}}
        lines.append(json.dumps(action, ensure_ascii=False, separators=(",", ":")))
        lines.append(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))

    payload = "\n".join(lines) + "\n"
    path.write_text(payload, encoding="utf-8")
    return len(docs)


def _validate_ndjson(path: Path, expected_lines: int) -> None:
    content = path.read_text(encoding="utf-8")
    if not content.endswith("\n"):
        raise ValueError(f"{path.name} must terminate with newline")

    lines = content.splitlines()
    if len(lines) != expected_lines:
        raise ValueError(f"{path.name} expected {expected_lines} lines, got {len(lines)}")

    for line_no, line in enumerate(lines, start=1):
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} line {line_no} is not valid JSON") from exc


def _siemize_canonical(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    out["@timestamp"] = _pick_timestamp(doc, "normalized_timestamp", "timestamp", "first_seen")
    out["event.dataset"] = "unifi.wifi"
    out["event.module"] = "unifi"
    out["event.kind"] = "event"
    out["event.category"] = doc.get("event_categories_seen") or doc.get("event_category")
    out["event.type"] = doc.get("canonical_event_type") or doc.get("event_type")
    out["event.id"] = doc.get("canonical_event_id")
    out["event.risk_score"] = doc.get("severity_score")
    out["event.severity"] = doc.get("severity_level")
    out["observer.ip"] = doc.get("source_ip")
    out["observer.name"] = doc.get("host")
    out["client.mac"] = doc.get("client_mac")
    out["access_point.mac"] = doc.get("ap_mac")
    out["wifi.radio"] = doc.get("radio")
    out["labels.detection_tags"] = doc.get("detection_tags")
    out["labels.incident_type"] = doc.get("incident_type")
    out["labels.canonical_event_type"] = doc.get("canonical_event_type")
    out["unifi.raw_event_count"] = doc.get("raw_event_count")
    out["unifi.duration_ms"] = doc.get("duration_ms")
    out["unifi.confidence_score"] = doc.get("confidence_score")
    out["unifi.incident_candidate"] = doc.get("incident_candidate")
    return out


def _siemize_incident(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    out["@timestamp"] = _pick_timestamp(doc, "first_seen", "last_seen", "timestamp")
    out["event.dataset"] = "unifi.incidents"
    out["event.module"] = "unifi"
    out["event.kind"] = "alert"
    out["event.id"] = doc.get("incident_id")
    out["incident.id"] = doc.get("incident_id")
    out["incident.type"] = doc.get("incident_type")
    out["incident.status"] = doc.get("status")
    out["incident.first_seen"] = doc.get("first_seen")
    out["incident.last_seen"] = doc.get("last_seen")
    out["incident.duration_seconds"] = doc.get("duration_seconds")
    out["incident.canonical_event_count"] = doc.get("canonical_event_count")
    out["incident.severity_score"] = doc.get("severity_score")
    out["incident.severity_level"] = doc.get("severity_level")
    out["incident.analyst_priority"] = doc.get("analyst_priority")
    out["incident.operational_impact_score"] = doc.get("operational_impact_score")
    out["incident.operational_impact_rank_score"] = doc.get("operational_impact_rank_score")
    out["incident.confidence_score"] = doc.get("confidence_score")
    out["client.mac"] = doc.get("client_mac")
    out["observer.ip"] = doc.get("source_ips")
    out["wifi.radios"] = doc.get("radios")
    out["access_point.macs"] = doc.get("ap_macs")
    out["labels.detection_tags"] = doc.get("detection_tags")
    out["message"] = doc.get("evidence_summary") or doc.get("why_it_matters")
    out["recommended_action"] = doc.get("recommended_action")
    return out


def _build_analyst_summary_doc(analyst_summary: dict[str, Any], incident_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary_id": "analyst-summary-current",
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event.dataset": "unifi.analyst_summary",
        "event.module": "unifi",
        "event.kind": "metric",
        "summary.executive_summary": analyst_summary.get("executive_summary"),
        "summary.true_incident_count": analyst_summary.get("true_incident_count") or incident_summary.get("total_incidents"),
        "summary.priority_distribution": analyst_summary.get("priority_distribution") or incident_summary.get("analyst_priority_distribution"),
        "summary.what_to_investigate_first": analyst_summary.get("what_to_investigate_first"),
        "summary.noise_or_suppressed_breakdown": analyst_summary.get("noise_or_suppressed_breakdown")
        or incident_summary.get("noise_or_suppressed_breakdown"),
        "summary.top_problematic_clients": analyst_summary.get("top_problematic_clients") or incident_summary.get("top_problematic_clients"),
        "summary.siem_readiness_notes": [
            "NDJSON bulk files generated with deterministic IDs.",
            "SIEM-friendly fields are additive and preserve original payload fields.",
        ],
        "summary.guardrails": {
            "no_parser_change": True,
            "no_canonicalizer_change": True,
            "no_detection_change": True,
            "no_suppression_change": True,
        },
    }


def _templates() -> dict[str, Any]:
    props = {
        "@timestamp": {"type": "date"},
        "normalized_timestamp": {"type": "date"},
        "first_seen": {"type": "date"},
        "last_seen": {"type": "date"},
        "event.id": {"type": "keyword"},
        "event.dataset": {"type": "keyword"},
        "event.module": {"type": "keyword"},
        "event.kind": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.type": {"type": "keyword"},
        "incident.id": {"type": "keyword"},
        "incident.type": {"type": "keyword"},
        "incident.status": {"type": "keyword"},
        "incident.analyst_priority": {"type": "keyword"},
        "severity_level": {"type": "keyword"},
        "client.mac": {"type": "keyword"},
        "observer.ip": {"type": "keyword"},
        "observer.name": {"type": "keyword"},
        "access_point.mac": {"type": "keyword"},
        "wifi.radio": {"type": "keyword"},
        "labels.detection_tags": {"type": "keyword"},
        "labels.incident_type": {"type": "keyword"},
        "labels.canonical_event_type": {"type": "keyword"},
        "severity_score": {"type": "float"},
        "event.risk_score": {"type": "float"},
        "confidence_score": {"type": "float"},
        "operational_impact_score": {"type": "float"},
        "operational_impact_rank_score": {"type": "float"},
        "raw_event_count": {"type": "integer"},
        "duration_ms": {"type": "long"},
        "incident.duration_seconds": {"type": "long"},
        "incident.canonical_event_count": {"type": "integer"},
        "message": {"type": "text"},
        "evidence_summary": {"type": "text"},
        "why_it_matters": {"type": "text"},
        "recommended_action": {"type": "text"},
        "sequence_summary": {"type": "object", "enabled": True},
        "ranking_factors": {"type": "object", "enabled": True},
        "summary": {"type": "object", "enabled": True},
        "quality_guardrails": {"type": "object", "enabled": True},
    }
    return {
        "index_templates": {
            "unifi-canonical-events": {"index_patterns": ["unifi-canonical-events*"], "template": {"mappings": {"properties": props}}},
            "unifi-incidents": {"index_patterns": ["unifi-incidents*"], "template": {"mappings": {"properties": props}}},
            "unifi-analyst-summary": {"index_patterns": ["unifi-analyst-summary*"], "template": {"mappings": {"properties": props}}},
        }
    }


def export_opensearch(output_dir: Path) -> dict[str, Any]:
    output_dir = Path(output_dir)
    source_files = {
        "enriched_canonical_events": output_dir / "enriched_canonical_events.json",
        "incidents": output_dir / "incidents.json",
        "incident_summary": output_dir / "incident_summary.json",
        "detection_summary": output_dir / "detection_summary.json",
        "analyst_summary": output_dir / "analyst_summary.json",
        "quality_report": output_dir / "quality_report.json",
    }

    enriched = _extract_docs(_load_json(source_files["enriched_canonical_events"]), "canonical_events")
    incidents = _extract_docs(_load_json(source_files["incidents"]), "incidents")
    incident_summary = _load_json(source_files["incident_summary"])
    detection_summary = _load_json(source_files["detection_summary"]) if source_files["detection_summary"].exists() else {}
    analyst_summary = _load_json(source_files["analyst_summary"])
    quality_report = _load_json(source_files["quality_report"])

    opensearch_dir = output_dir / "opensearch"
    opensearch_dir.mkdir(parents=True, exist_ok=True)

    canonical_docs = [_siemize_canonical(d) for d in enriched]
    incident_docs = [_siemize_incident(d) for d in incidents]
    analyst_docs = [_build_analyst_summary_doc(analyst_summary, incident_summary)]

    canonical_bulk = opensearch_dir / "canonical_events_bulk.ndjson"
    incidents_bulk = opensearch_dir / "incidents_bulk.ndjson"
    analyst_bulk = opensearch_dir / "analyst_summary_bulk.ndjson"
    template_file = opensearch_dir / "opensearch_index_templates.json"
    manifest_file = opensearch_dir / "export_manifest.json"

    canonical_count = _write_bulk(canonical_bulk, "unifi-canonical-events", canonical_docs, "canonical_event_id", "canonical")
    incident_count = _write_bulk(incidents_bulk, "unifi-incidents", incident_docs, "incident_id", "incident")
    analyst_count = _write_bulk(analyst_bulk, "unifi-analyst-summary", analyst_docs, "summary_id", "summary")
    _validate_ndjson(canonical_bulk, canonical_count * 2)
    _validate_ndjson(incidents_bulk, incident_count * 2)
    _validate_ndjson(analyst_bulk, analyst_count * 2)

    template_file.write_text(json.dumps(_templates(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_files": {k: str(v) for k, v in source_files.items()},
        "output_files": {
            "canonical_events_bulk": str(canonical_bulk),
            "incidents_bulk": str(incidents_bulk),
            "analyst_summary_bulk": str(analyst_bulk),
            "index_templates": str(template_file),
        },
        "document_counts": {
            "unifi-canonical-events": canonical_count,
            "unifi-incidents": incident_count,
            "unifi-analyst-summary": analyst_count,
        },
        "index_names": ["unifi-canonical-events", "unifi-incidents", "unifi-analyst-summary"],
        "guardrail_counts": {
            "total_raw_events": quality_report.get("total_raw_events"),
            "total_parsed_events": quality_report.get("total_parsed_events"),
            "total_canonical_events": quality_report.get("total_canonical_events"),
            "unknown_events": quality_report.get("unknown_event_count_total", quality_report.get("unknown_events")),
            "total_enriched_events": len(enriched),
            "incident_candidates": detection_summary.get("incident_candidates", incident_summary.get("incident_candidate_count")),
            "final_incidents": len(incidents),
            "analyst_priority_distribution": incident_summary.get("analyst_priority_distribution"),
        },
        "notes": [
            "No HTTP calls are executed; files are generated for offline ingestion.",
            "SIEM-friendly fields are additive and do not remove source fields.",
        ],
        "import_examples": {
            "canonical_bulk": "curl -XPOST 'http://localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary '@data/output/opensearch/canonical_events_bulk.ndjson'",
            "incidents_bulk": "curl -XPOST 'http://localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary '@data/output/opensearch/incidents_bulk.ndjson'",
            "analyst_summary_bulk": "curl -XPOST 'http://localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary '@data/output/opensearch/analyst_summary_bulk.ndjson'",
            "create_templates": "curl -XPUT 'http://localhost:9200/_index_template/unifi-templates' -H 'Content-Type: application/json' --data-binary '@data/output/opensearch/opensearch_index_templates.json'",
        },
    }
    manifest_file.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return {
        "canonical_docs_exported": canonical_count,
        "incident_docs_exported": incident_count,
        "analyst_summary_docs_exported": analyst_count,
        "output_directory": str(opensearch_dir),
        "manifest": str(manifest_file),
    }
