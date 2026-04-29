from pathlib import Path

from detection import run_detection_layer, run_incident_builder
from src.parser import parse_file


if __name__ == "__main__":
    input_file = Path("data/raw/syslog")
    output_dir = Path("data/output")
    parsed_output_file = output_dir / "parsed_events.json"
    canonical_output_file = output_dir / "canonical_events.json"
    parser_report_output_file = output_dir / "parser_report.json"
    quality_report_output_file = output_dir / "quality_report.json"
    disconnect_sequence_diagnostics_output_file = output_dir / "disconnect_sequence_diagnostics.json"
    unknown_events_output_file = output_dir / "unknown_events.json"
    unknown_summary_output_file = output_dir / "unknown_summary.json"
    unknown_samples_output_file = output_dir / "unknown_samples.json"
    enriched_canonical_output_file = output_dir / "enriched_canonical_events.json"
    detection_summary_output_file = output_dir / "detection_summary.json"
    incidents_output_file = output_dir / "incidents.json"
    incident_summary_output_file = output_dir / "incident_summary.json"
    analyst_summary_output_file = output_dir / "analyst_summary.json"

    include_raw_in_canonical_output = False
    export_parsed_events = True
    export_all_unknown_events = True
    max_unknown_samples_per_pattern = 3

    output_dir.mkdir(parents=True, exist_ok=True)
    parse_file(
        input_file,
        parsed_output_file,
        canonical_output_path=canonical_output_file,
        parser_report_output_path=parser_report_output_file,
        quality_report_output_path=quality_report_output_file,
        disconnect_sequence_diagnostics_output_path=disconnect_sequence_diagnostics_output_file,
        unknown_events_output_path=unknown_events_output_file,
        unknown_summary_output_path=unknown_summary_output_file,
        unknown_samples_output_path=unknown_samples_output_file,
        include_raw_in_canonical_output=include_raw_in_canonical_output,
        export_parsed_events=export_parsed_events,
        export_all_unknown_events=export_all_unknown_events,
        max_unknown_samples_per_pattern=max_unknown_samples_per_pattern,
    )

    detection_summary = run_detection_layer(
        canonical_input_path=canonical_output_file,
        enriched_output_path=enriched_canonical_output_file,
        summary_output_path=detection_summary_output_file,
    )

    print("\nDETECTION SUMMARY")
    print(f"- enriched events: {detection_summary.get('total_enriched_events', 0)}")
    print(f"- incident candidates: {detection_summary.get('incident_candidate_count', 0)}")
    print(f"- severity distribution: {detection_summary.get('severity_distribution', {})}")

    tags_distribution = detection_summary.get("detection_tags_distribution", {})
    top_tags = list(tags_distribution.items())[:5] if isinstance(tags_distribution, dict) else []
    print(f"- top detection tags: {top_tags}")

    disconnect_distribution = detection_summary.get("disconnect_diagnostic_distribution", {})
    ap_radio_specific_count = tags_distribution.get("ap_radio_specific_issue", 0) if isinstance(tags_distribution, dict) else 0
    print("\nDISCONNECT DIAGNOSTICS")
    print(f"- total wifi_disconnect_sequences: {detection_summary.get('event_type_risk_distribution', {}).get('wifi_disconnect_sequence', 0)}")
    print(f"- suspicious wifi_disconnect_sequences: {sum(disconnect_distribution.values()) if isinstance(disconnect_distribution, dict) else 0}")
    print(f"- probable duplicate noise: {detection_summary.get('probable_unifi_duplicate_noise_count', 0)}")
    print(f"- client flapping: {detection_summary.get('client_flapping_count', 0)}")
    print(f"- ap/radio specific: {ap_radio_specific_count}")
    print(
        f"- needs manual review: "
        f"{disconnect_distribution.get('needs_manual_review', 0) if isinstance(disconnect_distribution, dict) else 0}"
    )

    incident_summary = run_incident_builder(
        enriched_input_path=enriched_canonical_output_file,
        incidents_output_path=incidents_output_file,
        summary_output_path=incident_summary_output_file,
        analyst_summary_output_path=analyst_summary_output_file,
    )

    print("\nINCIDENT SUMMARY")
    print(f"- total incidents: {incident_summary.get('total_incidents', 0)}")
    print(f"- severity distribution: {incident_summary.get('severity_distribution', {})}")
    print(f"- incident type distribution: {incident_summary.get('incident_type_distribution', {})}")
    print(f"- top clients: {incident_summary.get('top_clients', [])[:5]}")
    print(f"- top source IPs: {incident_summary.get('top_source_ips', [])[:5]}")
