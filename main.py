from pathlib import Path

from src.parser import parse_file


if __name__ == "__main__":
    input_file = Path("data/raw/syslog")
    output_dir = Path("data/output")
    parsed_output_file = output_dir / "parsed_events.json"
    canonical_output_file = output_dir / "canonical_events.json"

    output_dir.mkdir(parents=True, exist_ok=True)
    parse_file(
        input_file,
        parsed_output_file,
        canonical_output_path=canonical_output_file,
    )
