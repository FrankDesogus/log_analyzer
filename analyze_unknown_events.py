#!/usr/bin/env python3
"""Build an investigation report for unknown/non-classified UniFi events."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

MAX_PATTERN_CONTEXT = 30
MAX_CONTEXT_EXAMPLES_PER_PATTERN = 3

MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INTERNAL_TS_RE = re.compile(r"\[\d+\.\d+\]")
PID_RE = re.compile(r"\[(\d{2,6})\]")
LONG_NUM_RE = re.compile(r"\b\d{4,}\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze unknown events and produce JSON + Markdown investigation reports."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        default=[],
        help="One or more JSON files to analyze (parsed/canonical/unknown).",
    )
    parser.add_argument("--parsed", nargs="*", default=[], help="Optional parsed_events JSON file(s).")
    parser.add_argument(
        "--canonical", nargs="*", default=[], help="Optional canonical_events JSON file(s)."
    )
    parser.add_argument("--unknown", nargs="*", default=[], help="Optional unknown_events JSON file(s).")
    parser.add_argument("--output-dir", default="reports", help="Output directory for generated report files.")
    return parser.parse_args()


def is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def is_unknownish(value: Any) -> bool:
    if is_blank(value):
        return True
    return str(value).strip().lower() == "unknown"


def is_system_or_unknown_category(value: Any) -> bool:
    if is_blank(value):
        return True
    normalized = str(value).strip().lower()
    return normalized in {"unknown", "system_event"}


def is_unknown_event(event: dict[str, Any], canonical_hint: bool = False) -> bool:
    parse_status = str(event.get("parse_status", "parsed") or "parsed").strip().lower()

    conditions = [
        parse_status != "parsed",
        is_unknownish(event.get("event_type")),
        is_system_or_unknown_category(event.get("event_category")),
    ]

    canonical_event_type = str(event.get("canonical_event_type", "") or "").strip().lower()
    event_types_seen = event.get("event_types_seen")
    client_mac = event.get("client_mac")
    radio = event.get("radio")

    if canonical_hint or any(
        key in event for key in ("canonical_event_type", "event_types_seen", "canonical_event_id")
    ):
        conditions.extend(
            [
                canonical_event_type == "wifi_unknown_sequence",
                client_mac is None and radio is None,
                not bool(event_types_seen),
            ]
        )

    return any(conditions)


def normalize_message_pattern(message: str) -> str:
    pattern = message.strip()
    if not pattern:
        return "<EMPTY_MESSAGE>"

    pattern = INTERNAL_TS_RE.sub("[<INTERNAL_TS>]", pattern)
    pattern = PID_RE.sub("[<PID>]", pattern)
    pattern = MAC_RE.sub("<MAC>", pattern)
    pattern = IP_RE.sub("<IP>", pattern)
    pattern = LONG_NUM_RE.sub("<NUM>", pattern)
    return pattern


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as infile:
        return json.load(infile)


def extract_event_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        preferred_keys = [
            "raw_events",
            "parsed_events",
            "canonical_events",
            "unknown_events",
            "events",
            "items",
            "data",
        ]
        for key in preferred_keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

        list_values = [v for v in payload.values() if isinstance(v, list)]
        if list_values:
            largest = max(list_values, key=len)
            return [item for item in largest if isinstance(item, dict)]

        return [payload]

    return []


def detect_dataset_type(path: Path, first_event: dict[str, Any] | None) -> str:
    name = path.name.lower()
    first_event = first_event or {}
    if "canonical" in name or "canonical_event_type" in first_event or "event_types_seen" in first_event:
        return "canonical"
    if "unknown" in name:
        return "unknown"
    return "raw"


def compact_event_view(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "line_number": event.get("line_number"),
        "event_type": event.get("event_type"),
        "event_category": event.get("event_category"),
        "canonical_event_type": event.get("canonical_event_type"),
        "process_name": event.get("process_name") or event.get("process"),
        "source_ip": event.get("source_ip"),
        "raw_message": event.get("raw_message"),
    }


def suggest_classification(pattern: str) -> tuple[str, str, str, str]:
    p = pattern.lower()

    def has(*keywords: str) -> bool:
        return any(keyword in p for keyword in keywords)

    if has("event_sta_leave", "sta_leave", "disassociated"):
        return ("wifi_disconnect", "wifi_client", "high", "Pattern includes disconnect/leave semantics")
    if has("sta_assoc", "associated", " assoc", "[assoc", "assoc_"):
        return ("wifi_association", "wifi_client", "high", "Pattern includes association keywords")
    if has("auth_req", "auth_rsp", "authentication"):
        return ("wifi_auth", "wifi_client", "high", "Pattern includes authentication keywords")
    if has("deauth", "de-auth"):
        return ("wifi_deauth", "wifi_client", "high", "Pattern includes deauthentication keywords")
    if has("dhcp", "dnsmasq"):
        return ("dhcp_network", "network_service", "medium", "Pattern suggests DHCP/DNS service activity")
    if has("wpa", "eapol", "handshake"):
        return ("wifi_security_auth", "wifi_security", "high", "Pattern includes WPA/EAPOL handshake indicators")
    if has("channel", "radar", "dfs"):
        return ("wifi_radio_channel", "wifi_radio", "medium", "Pattern mentions channel/radar/DFS")
    if has("error", "fail", "timeout"):
        return ("error_event", "system_error", "medium", "Pattern includes generic error/failure wording")
    return ("unknown_low_priority", "unknown", "low", "No strong classification keyword found")


def compute_priority(count: int, percentage: float, suggested_event_type: str) -> str:
    if suggested_event_type != "unknown_low_priority" and (count >= 10 or percentage >= 5.0):
        return "HIGH"
    if suggested_event_type == "unknown_low_priority":
        return "LOW"
    return "MEDIUM"


def main() -> int:
    args = parse_args()

    input_paths = [Path(p) for p in (args.input + args.parsed + args.canonical + args.unknown)]
    unique_paths: list[Path] = []
    seen_paths: set[Path] = set()
    for path in input_paths:
        resolved = path.expanduser()
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        unique_paths.append(resolved)

    if not unique_paths:
        raise SystemExit("No input files provided. Use --input and/or --parsed/--canonical/--unknown.")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    datasets: list[dict[str, Any]] = []

    for path in unique_paths:
        if not path.exists():
            print(f"[WARN] File not found, skipping: {path}")
            continue
        try:
            payload = load_json_file(path)
        except json.JSONDecodeError as exc:
            print(f"[WARN] Invalid JSON in {path}: {exc}")
            continue

        events = extract_event_list(payload)
        dataset_type = detect_dataset_type(path, events[0] if events else None)
        datasets.append({"path": str(path), "dataset_type": dataset_type, "events": events})

    total_events = 0
    total_unknown = 0
    total_unknown_canonical = 0
    total_unknown_raw = 0

    process_counter: Counter[str] = Counter()
    process_example: dict[str, str] = {}
    source_counter: Counter[str] = Counter()
    facility_severity_counter: Counter[tuple[str, str]] = Counter()
    facility_severity_example: dict[tuple[str, str], str] = {}

    pattern_stats: dict[str, dict[str, Any]] = {}
    pattern_occurrences: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)

    for dataset_idx, dataset in enumerate(datasets):
        dataset_type = dataset["dataset_type"]
        events = dataset["events"]
        total_events += len(events)

        canonical_hint = dataset_type == "canonical"

        for event_idx, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            if not is_unknown_event(event, canonical_hint=canonical_hint):
                continue

            total_unknown += 1
            if dataset_type == "canonical":
                total_unknown_canonical += 1
            else:
                total_unknown_raw += 1

            process_name = str(event.get("process_name") or event.get("process") or "<UNKNOWN_PROCESS>")
            source_ip = str(event.get("source_ip") or "<UNKNOWN_SOURCE_IP>")
            facility = str(event.get("facility") or "<UNKNOWN_FACILITY>")
            severity = str(event.get("severity") or "<UNKNOWN_SEVERITY>")
            raw_message = str(event.get("raw_message") or event.get("raw_line") or "")
            pattern = normalize_message_pattern(raw_message)

            process_counter[process_name] += 1
            source_counter[source_ip] += 1
            facility_severity_counter[(facility, severity)] += 1

            process_example.setdefault(process_name, raw_message)
            facility_severity_example.setdefault((facility, severity), raw_message)

            if pattern not in pattern_stats:
                pattern_stats[pattern] = {
                    "count": 0,
                    "process_names_seen": set(),
                    "source_ips_seen": set(),
                    "severities_seen": set(),
                    "example_raw_messages": [],
                    "example_line_numbers": [],
                }

            pstat = pattern_stats[pattern]
            pstat["count"] += 1
            pstat["process_names_seen"].add(process_name)
            pstat["source_ips_seen"].add(source_ip)
            pstat["severities_seen"].add(severity)
            if raw_message and len(pstat["example_raw_messages"]) < 5 and raw_message not in pstat["example_raw_messages"]:
                pstat["example_raw_messages"].append(raw_message)
            line_number = event.get("line_number")
            if line_number is not None and len(pstat["example_line_numbers"]) < 10:
                pstat["example_line_numbers"].append(line_number)

            pattern_occurrences[pattern].append((dataset_idx, event_idx))

    def pct(value: int) -> float:
        if total_unknown == 0:
            return 0.0
        return round((value / total_unknown) * 100, 2)

    unknown_by_process_name = [
        {
            "process_name": proc,
            "count": count,
            "percentage": pct(count),
            "example_raw_message": process_example.get(proc, ""),
        }
        for proc, count in process_counter.most_common()
    ]

    unknown_by_source_ip = [
        {"source_ip": ip, "count": count, "percentage": pct(count)}
        for ip, count in source_counter.most_common()
    ]

    unknown_by_facility_severity = [
        {
            "facility": facility,
            "severity": severity,
            "count": count,
            "example_raw_message": facility_severity_example.get((facility, severity), ""),
        }
        for (facility, severity), count in facility_severity_counter.most_common()
    ]

    unknown_message_patterns: list[dict[str, Any]] = []
    for pattern, values in sorted(pattern_stats.items(), key=lambda item: item[1]["count"], reverse=True):
        count = values["count"]
        unknown_message_patterns.append(
            {
                "pattern": pattern,
                "count": count,
                "percentage": pct(count),
                "process_names_seen": sorted(values["process_names_seen"]),
                "source_ips_seen": sorted(values["source_ips_seen"]),
                "severities_seen": sorted(values["severities_seen"]),
                "example_raw_messages": values["example_raw_messages"],
                "example_line_numbers": values["example_line_numbers"],
            }
        )

    top_patterns = unknown_message_patterns[:MAX_PATTERN_CONTEXT]
    unknown_context_samples: list[dict[str, Any]] = []
    for entry in top_patterns:
        pattern = entry["pattern"]
        occurrences = pattern_occurrences.get(pattern, [])
        examples: list[dict[str, Any]] = []

        for dataset_idx, event_idx in occurrences[:MAX_CONTEXT_EXAMPLES_PER_PATTERN]:
            dataset = datasets[dataset_idx]
            events = dataset["events"]
            current = events[event_idx]
            previous = [
                compact_event_view(events[idx])
                for idx in range(max(0, event_idx - 3), event_idx)
                if isinstance(events[idx], dict)
            ]
            next_events = [
                compact_event_view(events[idx])
                for idx in range(event_idx + 1, min(len(events), event_idx + 4))
                if isinstance(events[idx], dict)
            ]

            examples.append(
                {
                    "line_number": current.get("line_number"),
                    "raw_line": current.get("raw_line"),
                    "raw_message": current.get("raw_message"),
                    "previous_events": previous,
                    "next_events": next_events,
                }
            )

        unknown_context_samples.append({"pattern": pattern, "count": entry["count"], "examples": examples})

    suggested_classification_candidates: list[dict[str, Any]] = []
    for entry in unknown_message_patterns:
        pattern = entry["pattern"]
        suggested_event_type, suggested_event_category, confidence, reason = suggest_classification(pattern)
        suggested_classification_candidates.append(
            {
                "pattern": pattern,
                "count": entry["count"],
                "suggested_event_type": suggested_event_type,
                "suggested_event_category": suggested_event_category,
                "confidence": confidence,
                "reason": reason,
            }
        )

    report = {
        "summary": {
            "total_events_analyzed": total_events,
            "total_unknown_events": total_unknown,
            "unknown_percentage": round((total_unknown / total_events) * 100, 2) if total_events else 0.0,
            "total_unknown_canonical_events": total_unknown_canonical,
            "total_unknown_raw_events": total_unknown_raw,
            "input_files_analyzed": [dataset["path"] for dataset in datasets],
        },
        "unknown_by_process_name": unknown_by_process_name,
        "unknown_by_source_ip": unknown_by_source_ip,
        "unknown_by_facility_severity": unknown_by_facility_severity,
        "unknown_message_patterns": unknown_message_patterns,
        "unknown_context_samples": unknown_context_samples,
        "suggested_classification_candidates": suggested_classification_candidates,
    }

    json_out = output_dir / "unknown_investigation_report.json"
    md_out = output_dir / "unknown_investigation_report.md"

    json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_out.write_text(build_markdown_report(report), encoding="utf-8")

    print(f"Unknown investigation JSON report written to: {json_out}")
    print(f"Unknown investigation Markdown report written to: {md_out}")
    return 0


def build_markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    patterns = report["unknown_message_patterns"]
    suggestions = report["suggested_classification_candidates"]

    lines: list[str] = [
        "# Unknown Events Investigation Report",
        "",
        "## Summary",
        f"- Total events analyzed: **{summary['total_events_analyzed']}**",
        f"- Total unknown events: **{summary['total_unknown_events']}**",
        f"- Unknown percentage: **{summary['unknown_percentage']}%**",
        f"- Unknown canonical events: **{summary['total_unknown_canonical_events']}**",
        f"- Unknown raw events: **{summary['total_unknown_raw_events']}**",
        "",
        "## Top 20 unknown patterns",
        "",
        "| # | Count | % | Pattern |",
        "|---|---:|---:|---|",
    ]

    for idx, pattern in enumerate(patterns[:20], start=1):
        escaped = pattern["pattern"].replace("|", "\\|")
        lines.append(f"| {idx} | {pattern['count']} | {pattern['percentage']} | `{escaped}` |")

    lines.extend(["", "## Raw examples by top patterns", ""])
    for pattern in patterns[:20]:
        lines.append(f"### Pattern ({pattern['count']} events, {pattern['percentage']}%)")
        lines.append(f"`{pattern['pattern']}`")
        for msg in pattern.get("example_raw_messages", [])[:3]:
            lines.append(f"- {msg}")
        lines.append("")

    suggestion_lookup = {item["pattern"]: item for item in suggestions}
    lines.extend(["## Suggested classifications", ""])
    for pattern in patterns[:20]:
        suggestion = suggestion_lookup.get(pattern["pattern"])
        if suggestion is None:
            continue
        priority = compute_priority(
            suggestion["count"],
            pattern.get("percentage", 0.0),
            suggestion["suggested_event_type"],
        )
        lines.extend(
            [
                f"### {priority} - {suggestion['suggested_event_type']} ({suggestion['suggested_event_category']})",
                f"- Pattern: `{suggestion['pattern']}`",
                f"- Count: {suggestion['count']}",
                f"- Confidence: {suggestion['confidence']}",
                f"- Reason: {suggestion['reason']}",
                "",
            ]
        )

    lines.extend(["## Recommended next parser improvements", ""])
    improvements = []
    for pattern in patterns:
        suggestion = suggestion_lookup.get(pattern["pattern"])
        if suggestion is None:
            continue
        priority = compute_priority(
            suggestion["count"],
            pattern.get("percentage", 0.0),
            suggestion["suggested_event_type"],
        )
        improvements.append((priority, pattern["count"], pattern["pattern"], suggestion))

    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    improvements.sort(key=lambda item: (priority_order[item[0]], -item[1]))

    for priority, count, pattern, suggestion in improvements[:20]:
        lines.append(
            f"1. **{priority}** - Implement mapping for `{suggestion['suggested_event_type']}` "
            f"(count={count}, confidence={suggestion['confidence']}) from pattern `{pattern}`."
        )

    if len(improvements) == 0:
        lines.append("1. No unknown patterns detected; parser coverage appears complete for input set.")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
