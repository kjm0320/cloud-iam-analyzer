import json
import unittest
from urllib.parse import quote

from analyze_collected_trust import analyze_collected_trust


class TestCollectedTrust(unittest.TestCase):
    def make_document(self):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }],
        }

    def make_data(self):
        return {
            "account_id": "123456789012",
            "partition": "aws",
            "collected_at": "2026-09-28T00:00:00+00:00",
            "authorization_details": {
                "RoleDetailList": [{
                    "RoleName": "demo-role",
                    "Arn": "arn:aws:iam::123456789012:role/demo-role",
                    "AssumeRolePolicyDocument": self.make_document(),
                }]
            },
        }

    def test_finding_preserves_role_identity(self):
        report = analyze_collected_trust(self.make_data())

        self.assertEqual(report["summary"]["role_count"], 1)
        self.assertEqual(report["summary"]["analyzed_role_count"], 1)
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["skipped_role_count"], 0)

        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "IAM006")
        self.assertEqual(finding["role_name"], "demo-role")
        self.assertEqual(
            finding["role_arn"],
            "arn:aws:iam::123456789012:role/demo-role",
        )

    def test_condition_review_is_counted(self):
        data = self.make_data()
        document = (
            data["authorization_details"]["RoleDetailList"][0]
            ["AssumeRolePolicyDocument"]
        )
        document["Statement"][0]["Condition"] = {
            "StringEquals": {
                "aws:PrincipalOrgID": "o-example123"
            }
        }

        report = analyze_collected_trust(data)

        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(
            report["summary"]["condition_review_count"], 1
        )
        self.assertEqual(
            report["findings"][0]["review_status"],
            "condition_review",
        )

    def test_invalid_role_is_skipped_without_losing_valid_result(self):
        data = self.make_data()
        data["authorization_details"]["RoleDetailList"].append({
            "RoleName": "demo-invalid",
            "Arn": "arn:aws:iam::123456789012:role/demo-invalid",
        })

        report = analyze_collected_trust(data)

        self.assertEqual(report["summary"]["role_count"], 2)
        self.assertEqual(report["summary"]["analyzed_role_count"], 1)
        self.assertEqual(report["summary"]["skipped_role_count"], 1)
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(
            report["skipped_roles"][0]["role_name"],
            "demo-invalid",
        )
        self.assertTrue(report["skipped_roles"][0]["reason"])

    def test_json_and_url_encoded_documents_are_supported(self):
        plain = json.dumps(self.make_document())

        for document in (plain, quote(plain, safe="")):
            with self.subTest(document=document):
                data = self.make_data()
                data["authorization_details"]["RoleDetailList"][0][
                    "AssumeRolePolicyDocument"
                ] = document

                report = analyze_collected_trust(data)

                self.assertEqual(report["summary"]["finding_count"], 1)
                self.assertEqual(
                    report["summary"]["skipped_role_count"], 0
                )

    def test_duplicate_roles_are_rejected(self):
        data = self.make_data()
        roles = data["authorization_details"]["RoleDetailList"]
        roles.append(dict(roles[0]))

        with self.assertRaisesRegex(ValueError, "중복"):
            analyze_collected_trust(data)


if __name__ == "__main__":
    unittest.main()