import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collect_access_keys import collect_access_keys, format_timestamp


class TestCollectAccessKeys(unittest.TestCase):
    def make_metadata(self, key_id="DEMO_KEY"):
        return {
            "AccessKeyId": key_id,
            "Status": "Active",
            "CreateDate": datetime(
                2020, 1, 1, tzinfo=timezone.utc
            ),
        }

    def make_client(self):
        iam = MagicMock()
        user_paginator = MagicMock()
        key_paginator = MagicMock()

        iam.get_paginator.side_effect = {
            "list_users": user_paginator,
            "list_access_keys": key_paginator,
        }.__getitem__

        user_paginator.paginate.return_value = [
            {"Users": [{"UserName": "demo-user"}]}
        ]
        key_paginator.paginate.return_value = [
            {"AccessKeyMetadata": [self.make_metadata()]}
        ]
        iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "LastUsedDate": datetime(
                    2020, 2, 1, tzinfo=timezone.utc
                )
            }
        }

        return iam, user_paginator, key_paginator

    def test_used_key_metadata_is_collected(self):
        iam, _, key_paginator = self.make_client()

        result = collect_access_keys(iam)

        self.assertEqual(
            result["access_keys"],
            [{
                "user_name": "demo-user",
                "key_id": "DEMO_KEY",
                "status": "Active",
                "created_at": "2020-01-01T00:00:00+00:00",
                "usage_status": "used",
                "last_used_at": "2020-02-01T00:00:00+00:00",
            }],
        )
        self.assertEqual(result["source"], "aws_iam")
        self.assertIn("collected_at", result)
        self.assertNotIn("SecretAccessKey", result["access_keys"][0])

        key_paginator.paginate.assert_called_once_with(
            UserName="demo-user"
        )
        iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="DEMO_KEY"
        )

    def test_missing_last_used_date_becomes_unknown(self):
        iam, _, _ = self.make_client()
        iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "ServiceName": "N/A",
                "Region": "N/A",
            }
        }

        result = collect_access_keys(iam)
        key = result["access_keys"][0]

        self.assertEqual(key["usage_status"], "unknown")
        self.assertIsNone(key["last_used_at"])

    def test_missing_usage_structure_is_rejected(self):
        iam, _, _ = self.make_client()
        iam.get_access_key_last_used.return_value = {}

        with self.assertRaisesRegex(ValueError, "사용 정보 구조"):
            collect_access_keys(iam)

    def test_access_denied_stops_collection(self):
        iam, _, _ = self.make_client()
        iam.get_access_key_last_used.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "테스트용 접근 거부",
                }
            },
            "GetAccessKeyLastUsed",
        )

        with self.assertRaises(ClientError) as raised:
            collect_access_keys(iam)

        self.assertEqual(
            raised.exception.response["Error"]["Code"],
            "AccessDenied",
        )

    def test_all_user_and_key_pages_are_processed(self):
        iam, user_paginator, key_paginator = self.make_client()

        user_paginator.paginate.return_value = [
            {"Users": [{"UserName": "demo-z"}]},
            {"Users": [{"UserName": "demo-a"}]},
        ]
        key_paginator.paginate.side_effect = [
            [
                {
                    "AccessKeyMetadata": [
                        self.make_metadata("DEMO_Z1")
                    ]
                },
                {
                    "AccessKeyMetadata": [
                        self.make_metadata("DEMO_Z2")
                    ]
                },
            ],
            [
                {
                    "AccessKeyMetadata": [
                        self.make_metadata("DEMO_A1")
                    ]
                }
            ],
        ]

        result = collect_access_keys(iam)

        self.assertEqual(
            [
                (key["user_name"], key["key_id"])
                for key in result["access_keys"]
            ],
            [
                ("demo-a", "DEMO_A1"),
                ("demo-z", "DEMO_Z1"),
                ("demo-z", "DEMO_Z2"),
            ],
        )
        self.assertEqual(
            iam.get_access_key_last_used.call_count, 3
        )

    def test_user_without_keys_is_accepted(self):
        iam, _, key_paginator = self.make_client()
        key_paginator.paginate.return_value = [
            {"AccessKeyMetadata": []}
        ]

        result = collect_access_keys(iam)

        self.assertEqual(result["access_keys"], [])
        iam.get_access_key_last_used.assert_not_called()

    def test_timestamp_conversion_and_validation(self):
        korea_time = datetime(
            2020, 1, 1, 9, 0,
            tzinfo=timezone(timedelta(hours=9)),
        )

        self.assertEqual(
            format_timestamp(korea_time),
            "2020-01-01T00:00:00+00:00",
        )

        for value in (
            None,
            "2020-01-01",
            datetime(2020, 1, 1),
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    format_timestamp(value)


if __name__ == "__main__":
    unittest.main()