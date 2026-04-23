import json
import tempfile
import unittest
from pathlib import Path

from src import parser


class FineDuplicateBucketTests(unittest.TestCase):
    def test_bucket_10ms(self) -> None:
        self.assertEqual(parser.build_internal_event_bucket(773313.921726, bucket_ms=10), "773313.92")
        self.assertEqual(parser.build_internal_event_bucket(773313.927350, bucket_ms=10), "773313.92")

    def test_bucket_20ms(self) -> None:
        self.assertEqual(parser.build_internal_event_bucket(773313.921726, bucket_ms=20), "773313.92")
        self.assertEqual(parser.build_internal_event_bucket(773313.939999, bucket_ms=20), "773313.92")
        self.assertEqual(parser.build_internal_event_bucket(773313.940000, bucket_ms=20), "773313.94")

    def test_missing_internal_event_ts_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "in.log"
            output_path = Path(tmp) / "out.json"
            input_path.write_text(
                "10.0.0.1 Apr 23 12:00:00 ap daemon info hostapd: STA aa:bb:cc:dd:ee:ff associated\n",
                encoding="utf-8",
            )

            parser.parse_file(input_path, output_path)
            events = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertIsNone(event["internal_event_ts"])
            self.assertIsNone(event["internal_event_ts_float"])
            self.assertIsNone(event["internal_event_bucket"])
            self.assertIsNone(event["fine_duplicate_group_key"])
            self.assertEqual(event["fine_duplicate_group_size"], 1)
            self.assertFalse(event["is_fine_duplicate_candidate"])


if __name__ == "__main__":
    unittest.main()
