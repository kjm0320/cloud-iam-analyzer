import unittest

from build_relationships import build_relationships
from html_relationships import render_relationships
from passrole_relationships import build_passrole_reviews


PREFIX = "arn:aws:iam::123456789012:"
POLICY_ARN = PREFIX + "policy/demo-passrole"


def make_data():
    attached = [{"PolicyArn": POLICY_ARN}]

    return {
        "account_id": "123456789012",
        "collected_at": "2026-10-01T00:00:00+00:00",
        "authorization_details": {
            "Policies": [{
                "Arn": POLICY_ARN,
                "PolicyName": "demo-passrole",
                "DefaultVersionId": "v1",
                "PolicyVersionList": [{
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }],
                    },
                }],
            }],
            "UserDetailList": [
                {
                    "Arn": PREFIX + "user/direct-user",
                    "UserName": "direct-user",
                    "AttachedManagedPolicies": attached,
                },
                {
                    "Arn": PREFIX + "user/group-user",
                    "UserName": "group-user",
                    "GroupList": ["developers"],
                },
                {
                    "Arn": PREFIX + "user/boundary-user",
                    "UserName": "boundary-user",
                    "PermissionsBoundary": {
                        "PermissionsBoundaryArn": POLICY_ARN,
                    },
                },
            ],
            "GroupDetailList": [{
                "Arn": PREFIX + "group/developers",
                "GroupName": "developers",
                "AttachedManagedPolicies": attached,
            }],
            "RoleDetailList": [{
                "Arn": PREFIX + "role/demo-role",
                "RoleName": "demo-role",
                "AttachedManagedPolicies": attached,
            }],
        },
    }


def analyze(data):
    graph = build_relationships(data)
    return build_passrole_reviews(data, graph)


class PassRoleRelationshipTests(unittest.TestCase):
    def test_direct_and_group_connections(self):
        result = analyze(make_data())
        self.assertEqual(result["review_count"], 1)
        self.assertEqual(result["skipped_policies"], [])

        principals = {
            item["name"]: item
            for item in result["reviews"][0]["principals"]
        }

        self.assertEqual(
            set(principals),
            {"direct-user", "group-user", "demo-role"},
        )
        self.assertTrue(principals["direct-user"]["direct_attachment"])
        self.assertTrue(principals["demo-role"]["direct_attachment"])
        self.assertFalse(principals["group-user"]["direct_attachment"])
        self.assertEqual(
            principals["group-user"]["via_groups"],
            [PREFIX + "group/developers"],
        )

    def test_boundary_only_does_not_grant_permissions(self):
        data = make_data()
        details = data["authorization_details"]
        details["UserDetailList"] = [details["UserDetailList"][2]]
        details["GroupDetailList"] = []
        details["RoleDetailList"] = []

        result = analyze(data)

        self.assertEqual(result["reviews"], [])
        self.assertEqual(result["skipped_policies"], [])

    def test_non_default_version_is_not_analyzed(self):
        data = make_data()
        policy = data["authorization_details"]["Policies"][0]
        policy["PolicyVersionList"].append({
            "VersionId": "v2",
            "IsDefaultVersion": True,
            "Document": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
            },
        })
        policy["PolicyVersionList"][0]["IsDefaultVersion"] = False
        policy["DefaultVersionId"] = "v2"

        self.assertEqual(analyze(data)["reviews"], [])

    def test_missing_default_version_is_reported(self):
        data = make_data()
        data["authorization_details"]["Policies"][0][
            "PolicyVersionList"
        ] = []

        result = analyze(data)

        self.assertEqual(result["reviews"], [])
        self.assertEqual(len(result["skipped_policies"]), 1)
        self.assertEqual(
            result["skipped_policies"][0]["policy_arn"],
            POLICY_ARN,
        )

    def test_html_escapes_names_and_condition(self):
        data = make_data()
        payload = "<script>alert(1)</script>"
        policy = data["authorization_details"]["Policies"][0]
        policy["PolicyName"] = payload
        statement = policy["PolicyVersionList"][0]["Document"][
            "Statement"
        ][0]
        statement["Condition"] = {
            "StringEquals": {"iam:PassedToService": payload},
        }

        graph = build_relationships(data)
        graph["passrole_review"] = build_passrole_reviews(data, graph)
        page = render_relationships(graph)

        self.assertTrue(
            graph["passrole_review"]["reviews"][0]["has_condition"]
        )
        self.assertIn("PassRole 검토 대상", page)
        self.assertIn("group-user", page)
        self.assertNotIn(payload, page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()