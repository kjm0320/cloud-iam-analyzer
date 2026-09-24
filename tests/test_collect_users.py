import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collect_users import collect_users


class TestCollectUsers(unittest.TestCase):
    def make_client(self, user_pages=None, mfa_pages=None):
        iam = MagicMock()
        user_paginator = MagicMock()
        mfa_paginator = MagicMock()

        if user_pages is None:
            user_pages = [
                {"Users": [{"UserName": "demo-user"}]}
            ]

        if mfa_pages is None:
            mfa_pages = [{"MFADevices": []}]

        user_paginator.paginate.return_value = user_pages
        mfa_paginator.paginate.return_value = mfa_pages

        iam.get_paginator.side_effect = {
            "list_users": user_paginator,
            "list_mfa_devices": mfa_paginator,
        }.__getitem__

        iam.get_login_profile.return_value = {
            "LoginProfile": {"UserName": "demo-user"}
        }

        return iam, user_paginator, mfa_paginator

    def make_error(self, code, operation):
        return ClientError(
            {
                "Error": {
                    "Code": code,
                    "Message": "테스트용 오류",
                }
            },
            operation,
        )

    def test_console_user_with_mfa_is_collected(self):
        iam, _, mfa_paginator = self.make_client(
            mfa_pages=[
                {
                    "MFADevices": [
                        {"SerialNumber": "TEST_MFA_DEVICE"}
                    ]
                }
            ]
        )

        result = collect_users(iam)

        self.assertEqual(
            result["users"],
            [{
                "user_name": "demo-user",
                "console_access": True,
                "mfa_enabled": True,
            }],
        )
        self.assertEqual(result["source"], "aws_iam")
        self.assertIn("collected_at", result)

        iam.get_login_profile.assert_called_once_with(
            UserName="demo-user"
        )
        mfa_paginator.paginate.assert_called_once_with(
            UserName="demo-user"
        )

    def test_missing_login_profile_means_no_console_password(self):
        iam, _, _ = self.make_client()
        iam.get_login_profile.side_effect = self.make_error(
            "NoSuchEntity", "GetLoginProfile"
        )

        result = collect_users(iam)

        self.assertEqual(
            result["users"],
            [{
                "user_name": "demo-user",
                "console_access": False,
                "mfa_enabled": False,
            }],
        )

    def test_all_user_and_mfa_pages_are_processed(self):
        iam, user_paginator, mfa_paginator = self.make_client(
            user_pages=[
                {"Users": [{"UserName": "demo-z"}]},
                {"Users": [{"UserName": "demo-a"}]},
            ]
        )

        mfa_paginator.paginate.side_effect = [
            [
                {"MFADevices": []},
                {"MFADevices": [{"SerialNumber": "TEST_MFA"}]},
            ],
            [
                {"MFADevices": []},
            ],
        ]

        result = collect_users(iam)

        self.assertEqual(
            result["users"],
            [
                {
                    "user_name": "demo-a",
                    "console_access": True,
                    "mfa_enabled": False,
                },
                {
                    "user_name": "demo-z",
                    "console_access": True,
                    "mfa_enabled": True,
                },
            ],
        )
        user_paginator.paginate.assert_called_once_with()
        self.assertEqual(iam.get_login_profile.call_count, 2)
        self.assertEqual(mfa_paginator.paginate.call_count, 2)

    def test_login_profile_access_denied_stops_collection(self):
        iam, _, mfa_paginator = self.make_client()
        iam.get_login_profile.side_effect = self.make_error(
            "AccessDenied", "GetLoginProfile"
        )

        with self.assertRaises(ClientError) as raised:
            collect_users(iam)

        self.assertEqual(
            raised.exception.response["Error"]["Code"],
            "AccessDenied",
        )
        mfa_paginator.paginate.assert_not_called()

    def test_mfa_query_failure_stops_collection(self):
        for code in ("AccessDenied", "NoSuchEntity"):
            with self.subTest(code=code):
                iam, _, mfa_paginator = self.make_client()
                mfa_paginator.paginate.side_effect = self.make_error(
                    code, "ListMFADevices"
                )

                with self.assertRaises(ClientError) as raised:
                    collect_users(iam)

                self.assertEqual(
                    raised.exception.response["Error"]["Code"],
                    code,
                )

    def test_empty_user_list_is_accepted(self):
        iam, _, mfa_paginator = self.make_client(
            user_pages=[{"Users": []}]
        )

        result = collect_users(iam)

        self.assertEqual(result["users"], [])
        iam.get_login_profile.assert_not_called()
        mfa_paginator.paginate.assert_not_called()


if __name__ == "__main__":
    unittest.main()