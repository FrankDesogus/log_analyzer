from pathlib import Path

from src.parser import parse_file


if __name__ == "__main__":
    input_file = Path("data/raw/syslog")
    output_dir = Path("data/output")
    parsed_output_file = output_dir / "parsed_events.json"
    canonical_output_file = output_dir / "canonical_events.json"
    parser_report_output_file = output_dir / "parser_report.json"
    unknown_events_output_file = output_dir / "unknown_events.json"
    unknown_summary_output_file = output_dir / "unknown_summary.json"
    unknown_samples_output_file = output_dir / "unknown_samples.json"
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
        unknown_events_output_path=unknown_events_output_file,
        unknown_summary_output_path=unknown_summary_output_file,
        unknown_samples_output_path=unknown_samples_output_file,
        include_raw_in_canonical_output=include_raw_in_canonical_output,
        export_parsed_events=export_parsed_events,
        export_all_unknown_events=export_all_unknown_events,
        max_unknown_samples_per_pattern=max_unknown_samples_per_pattern,
    )
