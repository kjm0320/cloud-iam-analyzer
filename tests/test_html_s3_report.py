import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from html_s3_report import render_s3_html
from s3_analyzer import analyze_s3


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestHtmlS3Report(unittest.TestCase):
    def make_settings(self, restrict=False):
        return {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": restrict,
        }

    def make_data(self):
        return {
            "source": "synthetic",
            "account_public_access_block": self.make_settings(),
            "buckets": [
                {
                    "bucket_name": "demo-public",
                    "policy_status": "public",
                    "bucket_public_access_block": self.make_settings(),
                },
                {
                    "bucket_name": "demo-restricted",
                    "policy_status": "public",
                    "bucket_public_access_block": self.make_settings(True),
                },
                {
                    "bucket_name": "demo-nonpublic",
                    "policy_status": "nonpublic",
                    "bucket_public_access_block": self.make_settings(),
                },
                {
                    "bucket_name": "demo-unknown",
                    "policy_status": "unknown",
                    "bucket_public_access_block": self.make_settings(),
                },
            ],
        }

    def test_all_result_categories_are_displayed(self):
        report = analyze_s3(self.make_data())
        html = render_s3_html(report, "demo.json", "synthetic")

        for text in (
            "S3 공개 접근 점검",
            "공개용 가상 데이터",
            "검토 필요",
            "판단 불가",
            "제한 설정 확인",
            "규칙 해당 없음",
            "demo-public",
            "demo-restricted",
            "demo-nonpublic",
            "demo-unknown",
            "입력 및 분석 한계",
        ):
            with self.subTest(text=text):
                self.assertIn(text, html)

        self.assertEqual(report["summary"]["bucket_count"], 4)
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["unknown_count"], 1)
        self.assertEqual(report["summary"]["restricted_count"], 1)
        self.assertEqual(report["summary"]["not_flagged_count"], 1)

    def test_untrusted_text_is_escaped(self):
        data = self.make_data()
        payload = '<script>alert("테스트")</script>'
        data["buckets"][0]["bucket_name"] = payload

        report = analyze_s3(data)
        report["findings"][0]["message"] = payload
        report["findings"][0]["recommendation"] = payload
        report["limitations"] = [payload]

        html = render_s3_html(report, payload, "synthetic")

        self.assertNotIn(payload, html)
        self.assertNotIn("<script>", html)
        self.assertEqual(
            html.count(
                "&lt;script&gt;alert(&quot;테스트&quot;)&lt;/script&gt;"
            ),
            5,
        )

    def test_command_creates_html_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / "reports" / "s3.html"

            source.write_text(
                json.dumps(self.make_data()),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "html_s3_report.py"),
                    str(source),
                    "--output",
                    str(output),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

            html = output.read_text(encoding="utf-8")
            self.assertIn("S3 공개 접근 점검", html)
            self.assertIn("demo-public", html)

    def test_input_file_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            original = json.dumps(self.make_data())
            source.write_text(original, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "html_s3_report.py"),
                    str(source),
                    "--output",
                    str(source),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn(b"[ERROR]", result.stderr)
            self.assertEqual(
                source.read_text(encoding="utf-8"),
                original,
            )


if __name__ == "__main__":
    unittest.main()