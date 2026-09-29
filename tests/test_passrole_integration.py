import unittest

from scan_collected import build_collected_report
from html_collected_report import render_collected_html


class TestPassRoleIntegration(unittest.TestCase):
    def make_report(self, enabled=True, service="lambda.amazonaws.com"):
        metadata = {
            "source": "aws_iam",
            "collected_at": "2026-09-29T00:00:00+00:00",
            "account_id": "123456789012",
            "partition": "aws",
            "caller_arn": "arn:aws:iam::123456789012:user/demo",
        }
        policies = {
            **metadata,
            "authorization_details": {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [],
                "Policies": [{
                    "PolicyName": "demo-passrole",
                    "DefaultVersionId": "v1",
                    "PolicyVersionList": [{
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "Document": {
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "iam:PassRole",
                                "Resource": (
                                    "arn:aws:iam::123456789012:role/app-*"
                                ),
                                "Condition": {
                                    "StringEquals": {
                                        "iam:PassedToService": service
                                    }
                                },
                            }]
                        },
                    }],
                }],
            },
        }
        return build_collected_report(
            policies,
            {**metadata, "users": []},
            {**metadata, "access_keys": []},
            include_passrole=enabled,
        )

    def test_enabled_rule_is_included(self):
        report = self.make_report()

        self.assertIn("IAM008", report["enabled_rules"])
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["passrole_finding_count"], 1)
        self.assertEqual(report["findings"][0]["rule_id"], "IAM008")
        self.assertEqual(
            report["findings"][0]["policy_name"], "demo-passrole"
        )

    def test_disabled_rule_is_not_applied(self):
        report = self.make_report(enabled=False)

        self.assertNotIn("IAM008", report["enabled_rules"])
        self.assertEqual(report["summary"]["passrole_finding_count"], 0)
        self.assertEqual(report["findings"], [])

    def test_html_displays_scope_and_escapes_condition(self):
        payload = "<script>테스트</script>"
        report = self.make_report(service=payload)

        html = render_collected_html(report)

        self.assertIn("PassRole의 넓은 역할 허용 범위", html)
        self.assertIn("demo-passrole", html)
        self.assertIn("arn:aws:iam::123456789012:role/app-*", html)
        self.assertIn("iam:PassedToService", html)
        self.assertIn("조건 검토 필요", html)
        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;테스트&lt;/script&gt;", html)


if __name__ == "__main__":
    unittest.main()