import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from html_report import render_html


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestHtmlReport(unittest.TestCase):
    def make_report(self):
        return {
            "schema_version": "1.0",
            "key_data_collected_at": "2026-09-24T00:00:00Z",
            "summary": {
                "finding_count": 1,
                "unknown_count": 0,
                "user_count": 1,
                "access_key_count": 0,
            },
            "findings": [
                {
                    "rule_id": "IAM003",
                    "user_name": "demo-user",
                    "message": "콘솔 사용자 MFA 미설정",
                    "recommendation": "MFA를 설정하세요.",
                }
            ],
            "unknowns": [],
            "sources": {
                "policy": "policy.json",
                "users": "users.json",
                "keys": "keys.json",
            },
            "limitations": ["입력 데이터만 분석합니다."],
        }

    def test_report_contains_finding_and_sections(self):
        html = render_html(self.make_report())

        for text in (
            'lang="ko"',
            "보안 점검 보고서",
            "규칙별 탐지 현황",
            "탐지 상세",
            "판단 불가 항목",
            "분석 범위와 한계",
            "IAM003",
            "demo-user",
            "MFA를 설정하세요.",
        ):
            with self.subTest(text=text):
                self.assertIn(text, html)

    def test_untrusted_text_is_escaped(self):
        report = self.make_report()
        payload = '<script>alert("테스트")</script>'

        report["findings"][0]["user_name"] = payload
        report["findings"][0]["message"] = payload
        report["findings"][0]["recommendation"] = payload
        report["sources"]["users"] = payload
        report["limitations"] = [payload]
        report["unknowns"] = [
            {
                "user_name": payload,
                "key_id": payload,
                "message": payload,
            }
        ]

        html = render_html(report)

        escaped = (
            "&lt;script&gt;alert(&quot;테스트&quot;)&lt;/script&gt;"
        )
        self.assertNotIn(payload, html)
        self.assertNotIn("<script>", html)
        self.assertEqual(html.count(escaped), 8)

    def test_empty_report_explains_no_findings(self):
        report = self.make_report()
        report["findings"] = []
        report["summary"]["finding_count"] = 0

        html = render_html(report)

        self.assertIn(
            "현재 적용한 규칙에서 탐지된 항목이 없습니다.",
            html,
        )
        self.assertIn(
            "이 결과만으로 안전함을 판단할 수는 없습니다.",
            html,
        )
        self.assertIn("보고된 판단 불가 항목이 없습니다.", html)

    def test_unknown_item_is_displayed(self):
        report = self.make_report()
        report["unknowns"] = [
            {
                "user_name": "demo-unknown",
                "key_id": "DEMO_UNKNOWN_KEY",
                "message": "사용 정보를 확인할 수 없습니다.",
            }
        ]
        report["summary"]["unknown_count"] = 1

        html = render_html(report)

        self.assertIn("demo-unknown", html)
        self.assertIn("DEMO_UNKNOWN_KEY", html)
        self.assertIn("사용 정보를 확인할 수 없습니다.", html)

    def test_invalid_report_is_rejected(self):
        cases = [
            [],
            {},
            {
                "findings": ["잘못된 항목"],
                "unknowns": [],
                "summary": {},
            },
        ]

        for report in cases:
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    render_html(report)

    def test_command_creates_html_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            output = Path(directory) / "html" / "report.html"

            source.write_text(
                json.dumps(self.make_report(), ensure_ascii=False),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "html_report.py"),
                    str(source),
                    "--output",
                    str(output),
                ],
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

            html = output.read_text(encoding="utf-8")
            self.assertIn("보안 점검 보고서", html)
            self.assertIn("demo-user", html)

    def test_input_file_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            original = json.dumps(self.make_report())

            source.write_text(original, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "html_report.py"),
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