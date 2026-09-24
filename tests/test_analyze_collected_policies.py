import json
import unittest
from urllib.parse import quote

from analyze_collected_policies import analyze_collected_policies


class TestCollectedPolicyAnalysis(unittest.TestCase):
    def make_document(self, action="*"):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
            }],
        }

    def make_data(self):
        return {
            "collected_at": "2026-09-24T00:00:00+00:00",
            "authorization_details": {
                "Policies": [],
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [],
            },
        }

    def add_managed_policy(self, data, document):
        policy = {
            "PolicyName": "demo-managed",
            "Arn": "arn:aws:iam::123456789012:policy/demo-managed",
            "DefaultVersionId": "v1",
            "PolicyVersionList": [{
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": document,
            }],
        }
        data["authorization_details"]["Policies"].append(policy)
        return policy

    def test_managed_policy_finding_keeps_identity(self):
        data = self.make_data()
        self.add_managed_policy(data, self.make_document())

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["finding_count"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "IAM001")
        self.assertEqual(finding["policy_name"], "demo-managed")
        self.assertEqual(finding["policy_type"], "managed")
        self.assertEqual(finding["version_id"], "v1")

    def test_old_non_default_version_is_not_analyzed(self):
        data = self.make_data()
        policy = self.add_managed_policy(
            data, self.make_document("s3:GetObject")
        )
        policy["PolicyVersionList"].append({
            "VersionId": "v2",
            "IsDefaultVersion": False,
            "Document": self.make_document(),
        })

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["analyzed_policy_count"], 1)
        self.assertEqual(report["findings"], [])

    def test_inline_policies_keep_owner_information(self):
        data = self.make_data()
        details = data["authorization_details"]

        for entity_field, name_field, policy_field, owner_type in (
            ("UserDetailList", "UserName", "UserPolicyList", "user"),
            ("GroupDetailList", "GroupName", "GroupPolicyList", "group"),
            ("RoleDetailList", "RoleName", "RolePolicyList", "role"),
        ):
            details[entity_field].append({
                name_field: f"demo-{owner_type}",
                policy_field: [{
                    "PolicyName": "demo-inline",
                    "PolicyDocument": self.make_document("s3:*"),
                }],
            })

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["analyzed_policy_count"], 3)
        self.assertEqual(report["summary"]["finding_count"], 3)
        self.assertEqual(
            {
                (item["owner_type"], item["owner_name"])
                for item in report["findings"]
            },
            {
                ("user", "demo-user"),
                ("group", "demo-group"),
                ("role", "demo-role"),
            },
        )
        self.assertTrue(
            all(
                item["rule_id"] == "IAM002"
                for item in report["findings"]
            )
        )

    def test_unsupported_policy_is_recorded_as_skipped(self):
        data = self.make_data()
        document = {
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*",
            }]
        }
        self.add_managed_policy(data, document)

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["analyzed_policy_count"], 0)
        self.assertEqual(report["summary"]["skipped_policy_count"], 1)
        self.assertEqual(report["findings"], [])
        self.assertIn(
            "NotAction",
            report["skipped_policies"][0]["reason"],
        )

    def test_missing_default_version_is_skipped(self):
        data = self.make_data()
        policy = self.add_managed_policy(data, self.make_document())
        policy["DefaultVersionId"] = "v9"

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["skipped_policy_count"], 1)
        self.assertEqual(report["summary"]["analyzed_policy_count"], 0)
        self.assertEqual(report["findings"], [])

    def test_json_and_url_encoded_documents_are_supported(self):
        document = self.make_document()
        plain = json.dumps(document)

        for value in (plain, quote(plain, safe="")):
            with self.subTest(document=value):
                data = self.make_data()
                self.add_managed_policy(data, value)

                report = analyze_collected_policies(data)

                self.assertEqual(report["summary"]["finding_count"], 1)
                self.assertEqual(
                    report["summary"]["skipped_policy_count"], 0
                )

    def test_role_trust_policy_is_not_analyzed_as_permissions(self):
        data = self.make_data()
        data["authorization_details"]["RoleDetailList"].append({
            "RoleName": "demo-role",
            "AssumeRolePolicyDocument": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }]
            },
            "RolePolicyList": [],
        })

        report = analyze_collected_policies(data)

        self.assertEqual(report["summary"]["candidate_policy_count"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["skipped_policies"], [])


if __name__ == "__main__":
    unittest.main()