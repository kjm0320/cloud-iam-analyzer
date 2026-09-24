import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collect_policies import collect_policies, serialize_datetime


class TestCollectPolicies(unittest.TestCase):
    def make_client(self, pages):
        iam = MagicMock()
        paginator = MagicMock()
        iam.get_paginator.return_value = paginator
        paginator.paginate.return_value = pages
        return iam, paginator

    def test_all_pages_and_policy_documents_are_preserved(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        }
        inline_policy = {
            "PolicyName": "demo-inline",
            "PolicyDocument": document,
        }
        managed_policy = {
            "PolicyName": "demo-managed",
            "DefaultVersionId": "v1",
            "PolicyVersionList": [{
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": document,
            }],
        }

        iam, paginator = self.make_client([
            {
                "UserDetailList": [{
                    "UserName": "demo-user",
                    "UserPolicyList": [inline_policy],
                }],
                "Policies": [managed_policy],
            },
            {
                "GroupDetailList": [{
                    "GroupName": "demo-group",
                    "GroupPolicyList": [inline_policy],
                }],
                "RoleDetailList": [{
                    "RoleName": "demo-role",
                    "RolePolicyList": [inline_policy],
                }],
            },
        ])

        result = collect_policies(iam)

        self.assertEqual(
            result["summary"],
            {
                "user_count": 1,
                "group_count": 1,
                "role_count": 1,
                "managed_policy_count": 1,
                "inline_policy_count": 3,
            },
        )
        details = result["authorization_details"]
        self.assertEqual(details["Policies"], [managed_policy])
        self.assertEqual(
            details["UserDetailList"][0]["UserPolicyList"],
            [inline_policy],
        )

        iam.get_paginator.assert_called_once_with(
            "get_account_authorization_details"
        )
        paginator.paginate.assert_called_once_with()

    def test_access_denied_stops_collection(self):
        iam, paginator = self.make_client([])
        paginator.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "테스트용 접근 거부",
                }
            },
            "GetAccountAuthorizationDetails",
        )

        with self.assertRaises(ClientError) as raised:
            collect_policies(iam)

        self.assertEqual(
            raised.exception.response["Error"]["Code"],
            "AccessDenied",
        )

    def test_missing_response_and_invalid_lists_are_rejected(self):
        cases = [
            [],
            [{"Policies": "잘못된 형식"}],
            [{"UserDetailList": ["잘못된 항목"]}],
            [{
                "RoleDetailList": [{
                    "RoleName": "demo-role",
                    "RolePolicyList": {},
                }]
            }],
        ]

        for pages in cases:
            with self.subTest(pages=pages):
                iam, _ = self.make_client(pages)

                with self.assertRaises(ValueError):
                    collect_policies(iam)

    def test_collected_dates_can_be_saved_as_json(self):
        iam, _ = self.make_client([
            {
                "UserDetailList": [{
                    "UserName": "demo-user",
                    "CreateDate": datetime(
                        2020, 1, 1, tzinfo=timezone.utc
                    ),
                }]
            }
        ])

        result = collect_policies(iam)
        serialized = json.dumps(
            result,
            default=serialize_datetime,
        )
        restored = json.loads(serialized)

        self.assertEqual(
            restored["authorization_details"]
            ["UserDetailList"][0]["CreateDate"],
            "2020-01-01T00:00:00+00:00",
        )

        with self.assertRaises(ValueError):
            serialize_datetime(datetime(2020, 1, 1))


if __name__ == "__main__":
    unittest.main()