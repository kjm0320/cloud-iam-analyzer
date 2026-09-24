import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scan import build_report, load_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"


class TestCombinedScan(unittest.TestCase):
    def load_inputs(self):
        return (
            load_json(SAMPLES / "admin_policy.json"),
            load_json(SAMPLES / "users.json"),
            load_json(SAMPLES / "unused_access_keys.json"),
        )

    def test_combined_rule_counts(self):
        report = build_report(*self.load_inputs())

        counts = Counter(
            finding["rule_id"]
            for finding in report["findings"]
        )

        self.assertEqual(
            counts,
            {
                "IAM001": 1,
                "IAM003": 1,
                "IAM004": 4,
                "IAM005": 2,
            },
        )
        self.assertEqual(report["summary"]["finding_count"], 8)
        self.assertEqual(report["summary"]["user_count"], 3)
        self.assertEqual(report["summary"]["access_key_count"], 4)

    def test_unknown_usage_is_preserved(self):
        report = build_report(*self.load_inputs())

        self.assertEqual(report["summary"]["unknown_count"], 1)
        self.assertEqual(len(report["unknowns"]), 1)
        self.assertEqual(
            report["unknowns"][0]["key_id"],
            "DEMO_USAGE_UNKNOWN",
        )

        unknown_key_rules = {
            finding["rule_id"]
            for finding in report["findings"]
            if finding.get("key_id") == "DEMO_USAGE_UNKNOWN"
        }

        self.assertEqual(unknown_key_rules, {"IAM004"})

    def test_invalid_policy_is_rejected(self):
        policy, users, keys = self.load_inputs()
        del policy["Statement"][0]["Effect"]

        with self.assertRaisesRegex(ValueError, "Effect"):
            build_report(policy, users, keys)

    def test_command_saves_combined_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reports" / "combined.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "scan.py"),
                    "--policy",
                    str(SAMPLES / "admin_policy.json"),
                    "--users",
                    str(SAMPLES / "users.json"),
                    "--keys",
                    str(SAMPLES / "unused_access_keys.json"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

            report = json.loads(
                output.read_text(encoding="utf-8")
            )

            self.assertEqual(report["schema_version"], "1.0")
            self.assertEqual(report["summary"]["finding_count"], 8)
            self.assertEqual(report["summary"]["unknown_count"], 1)
            self.assertEqual(
                report["sources"],
                {
                    "policy": "admin_policy.json",
                    "users": "users.json",
                    "keys": "unused_access_keys.json",
                },
            )


if __name__ == "__main__":
    unittest.main()