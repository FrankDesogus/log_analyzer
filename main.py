from pathlib import Path

from src.parser import parse_file


if __name__ == "__main__":
    input_file = Path("data/raw/syslog")
    output_file = Path("data/output/parsed_events.json")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    parse_file(input_file, output_file)
