import unittest

from scan_collected import build_collected_report
from html_collected_report import render_collected_html


class TestTrustIntegration(unittest.TestCase):
    def make_inputs(self):
        metadata = {
            "source": "aws_iam",
            "collected_at": "2026-09-28T00:00:00+00:00",
            "account_id": "123456789012",
            "partition": "aws",
            "caller_arn": (
                "arn:aws:iam::123456789012:user/demo-collector"
            ),
        }

        policies = {
            **metadata,
            "authorization_details": {
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
                "RoleDetailList": [{
                    "RoleName": "demo-open-role",
                    "Arn": (
                        "arn:aws:iam::123456789012:role/demo-open-role"
                    ),
                    "RolePolicyList": [],
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }],
                    },
                }],
            },
        }

        users = {
            **metadata,
            "users": [],
        }

        keys = {
            **metadata,
            "access_keys": [],
        }

        return policies, users, keys

    def test_trust_finding_is_included_in_combined_report(self):
        report = build_collected_report(*self.make_inputs())
        summary = report["summary"]

        self.assertEqual(summary["role_count"], 1)
        self.assertEqual(summary["analyzed_role_count"], 1)
        self.assertEqual(summary["skipped_role_count"], 0)
        self.assertEqual(summary["trust_finding_count"], 1)
        self.assertEqual(summary["finding_count"], 1)
        self.assertEqual(
            summary["trust_condition_review_count"], 0
        )
        self.assertEqual(report["findings"][0]["rule_id"], "IAM006")
        self.assertEqual(
            report["findings"][0]["role_name"],
            "demo-open-role",
        )

    def test_condition_and_role_name_are_escaped_in_html(self):
        policies, users, keys = self.make_inputs()
        role = policies["authorization_details"]["RoleDetailList"][0]
        payload = "<script>테스트</script>"

        role["RoleName"] = payload
        role["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = {
            "StringEquals": {
                "aws:PrincipalOrgID": payload
            }
        }

        report = build_collected_report(policies, users, keys)
        html = render_collected_html(report)

        self.assertEqual(
            report["summary"]["trust_condition_review_count"], 1
        )
        self.assertIn("IAM006", html)
        self.assertIn("역할 신뢰 정책 분석 현황", html)
        self.assertIn("조건 검토 필요", html)
        self.assertIn("aws:PrincipalOrgID", html)
        self.assertNotIn(payload, html)
        self.assertIn(
            "&lt;script&gt;테스트&lt;/script&gt;",
            html,
        )

    def test_skipped_role_is_preserved_and_displayed(self):
        policies, users, keys = self.make_inputs()
        policies["authorization_details"]["RoleDetailList"].append({
            "RoleName": "demo-missing-trust",
            "RolePolicyList": [],
        })

        report = build_collected_report(policies, users, keys)
        html = render_collected_html(report)

        self.assertEqual(report["summary"]["role_count"], 2)
        self.assertEqual(
            report["summary"]["analyzed_role_count"], 1
        )
        self.assertEqual(
            report["summary"]["skipped_role_count"], 1
        )
        self.assertEqual(
            report["skipped_roles"][0]["role_name"],
            "demo-missing-trust",
        )
        self.assertIn("신뢰 정책 분석 제외 역할과 사유", html)
        self.assertIn("demo-missing-trust", html)
        self.assertIn(
            report["skipped_roles"][0]["reason"],
            html,
        )


if __name__ == "__main__":
    unittest.main()