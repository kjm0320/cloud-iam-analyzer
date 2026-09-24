import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER = PROJECT_ROOT / "analyzer.py"


class TestJsonReport(unittest.TestCase):
    def test_report_is_created_in_new_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reports" / "result.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER),
                    str(PROJECT_ROOT / "samples" / "service_wildcard_policy.json"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

            report = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(report["schema_version"], "1.0")
            self.assertEqual(
                report["source"],
                "service_wildcard_policy.json",
            )
            self.assertEqual(report["finding_count"], 1)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["rule_id"], "IAM002")

    def test_input_file_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            original = json.dumps({
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            })
            policy.write_text(original, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER),
                    str(policy),
                    "--output",
                    str(policy),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn(b"[ERROR]", result.stderr)
            self.assertEqual(
                policy.read_text(encoding="utf-8"),
                original,
            )


if __name__ == "__main__":
    unittest.main()