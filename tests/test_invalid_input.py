import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER = PROJECT_ROOT / "analyzer.py"


class TestInvalidInput(unittest.TestCase):
    def test_invalid_policy_fails_without_creating_report(self):
        cases = {
            "missing_effect": {
                "Action": "*",
                "Resource": "*",
            },
            "missing_action": {
                "Effect": "Allow",
                "Resource": "*",
            },
            "empty_resource": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": [],
            },
            "unsupported_not_action": {
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*",
            },
        }

        for name, statement in cases.items():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as directory:
                    policy = Path(directory) / "policy.json"
                    output = Path(directory) / "report.json"

                    policy.write_text(
                        json.dumps({"Statement": [statement]}),
                        encoding="utf-8",
                    )

                    result = subprocess.run(
                        [
                            sys.executable,
                            str(ANALYZER),
                            str(policy),
                            "--output",
                            str(output),
                        ],
                        capture_output=True,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(b"[ERROR]", result.stderr)
                    self.assertNotIn(b"Traceback", result.stderr)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()