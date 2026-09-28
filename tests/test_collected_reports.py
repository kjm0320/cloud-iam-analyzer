import copy
import unittest

from scan_collected import build_collected_report
from html_collected_report import render_collected_html


class TestCollectedReports(unittest.TestCase):
    def make_inputs(self):
        metadata = {
            "source": "aws_iam",
            "collected_at": "2026-09-24T00:00:00+00:00",
            "account_id": "123456789012",
            "partition": "aws",
            "caller_arn": (
                "arn:aws:iam::123456789012:user/demo-collector"
            ),
        }

        policies = {
            **metadata,
            "authorization_details": {
                "UserDetailList": [{"UserName": "demo-user"}],
                "GroupDetailList": [],
                "RoleDetailList": [],
                "Policies": [{
                    "PolicyName": "demo-policy",
                    "DefaultVersionId": "v1",
                    "PolicyVersionList": [{
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "Document": {
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }]
                        },
                    }],
                }],
            },
        }

        users = {
            **metadata,
            "users": [{
                "user_name": "demo-user",
                "console_access": True,
                "mfa_enabled": False,
            }],
        }

        keys = {
            **metadata,
            "access_keys": [{
                "user_name": "demo-user",
                "key_id": "DEMO_KEY",
                "status": "Active",
                "created_at": "2020-01-01T00:00:00+00:00",
                "usage_status": "used",
                "last_used_at": "2020-02-01T00:00:00+00:00",
            }],
        }

        return policies, users, keys

    def test_all_analysis_results_are_combined(self):
        report = build_collected_report(*self.make_inputs())

        self.assertEqual(report["report_type"], "aws_collected")
        self.assertEqual(report["account_id"], "123456789012")
        self.assertEqual(report["partition"], "aws")
        self.assertEqual(report["summary"]["finding_count"], 4)
        self.assertEqual(report["summary"]["user_count"], 1)
        self.assertEqual(report["summary"]["access_key_count"], 1)
        self.assertEqual(
            report["summary"]["analyzed_policy_count"], 1
        )
        self.assertEqual(
            {item["rule_id"] for item in report["findings"]},
            {"IAM001", "IAM003", "IAM004", "IAM005"},
        )

    def test_unknown_usage_is_kept_separate(self):
        policies, users, keys = self.make_inputs()
        keys["access_keys"][0]["usage_status"] = "unknown"
        keys["access_keys"][0]["last_used_at"] = None

        report = build_collected_report(policies, users, keys)

        self.assertEqual(report["summary"]["finding_count"], 3)
        self.assertEqual(report["summary"]["unknown_count"], 1)
        self.assertEqual(report["unknowns"][0]["key_id"], "DEMO_KEY")
        self.assertNotIn(
            "IAM005",
            {item["rule_id"] for item in report["findings"]},
        )

    def test_unsupported_policy_is_preserved_as_skipped(self):
        policies, users, keys = self.make_inputs()
        document = (
            policies["authorization_details"]["Policies"][0]
            ["PolicyVersionList"][0]["Document"]
        )
        statement = document["Statement"][0]
        del statement["Action"]
        statement["NotAction"] = "iam:*"

        report = build_collected_report(policies, users, keys)

        self.assertEqual(
            report["summary"]["analyzed_policy_count"], 0
        )
        self.assertEqual(
            report["summary"]["skipped_policy_count"], 1
        )
        self.assertEqual(
            report["skipped_policies"][0]["policy_name"],
            "demo-policy",
        )
        self.assertIn(
            "NotAction",
            report["skipped_policies"][0]["reason"],
        )

    def test_inconsistent_user_data_is_rejected(self):
        for case in ("policy_users", "key_owner"):
            with self.subTest(case=case):
                policies, users, keys = self.make_inputs()

                if case == "policy_users":
                    policies["authorization_details"][
                        "UserDetailList"
                    ] = []
                else:
                    keys["access_keys"][0]["user_name"] = "other-user"

                with self.assertRaises(ValueError):
                    build_collected_report(policies, users, keys)

    def test_non_aws_source_is_rejected(self):
        for index in range(3):
            with self.subTest(input_index=index):
                inputs = list(self.make_inputs())
                inputs[index]["source"] = "sample"

                with self.assertRaisesRegex(ValueError, "AWS 수집기"):
                    build_collected_report(*inputs)

    def test_html_displays_policy_context_and_escapes_text(self):
        report = build_collected_report(*self.make_inputs())
        payload = "<script>테스트</script>"

        report["findings"][0]["policy_name"] = payload
        report["skipped_policies"] = [{
            "policy_name": payload,
            "owner_name": payload,
            "reason": payload,
        }]
        report["summary"]["skipped_policy_count"] = 1

        html = render_collected_html(report)

        self.assertIn("관리형 정책:", html)
        self.assertIn("기본 버전: v1", html)
        self.assertIn("분석 제외 정책과 사유", html)
        self.assertIn("데이터별 수집 시각", html)
        self.assertIn("2026-09-24T00:00:00+00:00", html)
        self.assertNotIn(payload, html)
        self.assertIn(
            "&lt;script&gt;테스트&lt;/script&gt;",
            html,
        )

    def test_html_rendering_does_not_modify_report(self):
        report = build_collected_report(*self.make_inputs())
        original = copy.deepcopy(report)

        render_collected_html(report)

        self.assertEqual(report, original)

    def test_different_accounts_are_rejected(self):
        policies, users, keys = self.make_inputs()
        keys["account_id"] = "999999999999"
        keys["caller_arn"] = (
            "arn:aws:iam::999999999999:user/demo-collector"
        )

        with self.assertRaisesRegex(ValueError, "서로 다릅니다"):
            build_collected_report(policies, users, keys)

    def test_missing_or_inconsistent_identity_is_rejected(self):
        for case in ("missing_account", "invalid_account", "wrong_arn"):
            with self.subTest(case=case):
                policies, users, keys = self.make_inputs()

                if case == "missing_account":
                    del users["account_id"]
                elif case == "invalid_account":
                    users["account_id"] = "123"
                else:
                    users["caller_arn"] = (
                        "arn:aws:iam::999999999999:user/demo-collector"
                    )

                with self.assertRaises(ValueError):
                    build_collected_report(policies, users, keys)

    def test_different_partitions_are_rejected(self):
        policies, users, keys = self.make_inputs()
        keys["partition"] = "aws-cn"
        keys["caller_arn"] = (
            "arn:aws-cn:iam::123456789012:user/demo-collector"
        )

        with self.assertRaisesRegex(ValueError, "서로 다릅니다"):
            build_collected_report(policies, users, keys)


if __name__ == "__main__":
    unittest.main()