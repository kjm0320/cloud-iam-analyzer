import unittest

from s3_analyzer import analyze_s3


class TestS3Analyzer(unittest.TestCase):
    def make_settings(self, restrict=False):
        return {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": restrict,
        }

    def make_data(self):
        return {
            "account_public_access_block": self.make_settings(),
            "buckets": [{
                "bucket_name": "demo-bucket",
                "policy_status": "public",
                "bucket_public_access_block": self.make_settings(),
            }],
        }

    def test_block_public_policy_alone_does_not_suppress_finding(self):
        report = analyze_s3(self.make_data())

        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["findings"][0]["rule_id"], "IAM007")
        self.assertFalse(
            report["findings"][0]["effective_restrict_public_buckets"]
        )

    def test_either_level_can_restrict_public_policy(self):
        for level in ("account", "bucket"):
            with self.subTest(level=level):
                data = self.make_data()

                if level == "account":
                    data["account_public_access_block"] = (
                        self.make_settings(restrict=True)
                    )
                else:
                    data["buckets"][0]["bucket_public_access_block"] = (
                        self.make_settings(restrict=True)
                    )

                report = analyze_s3(data)

                self.assertEqual(report["summary"]["finding_count"], 0)
                self.assertEqual(report["summary"]["restricted_count"], 1)
                self.assertEqual(report["summary"]["unknown_count"], 0)

    def test_unknown_settings_do_not_mean_disabled(self):
        for level in ("account", "bucket", "both"):
            with self.subTest(level=level):
                data = self.make_data()

                if level in ("account", "both"):
                    data["account_public_access_block"] = None
                if level in ("bucket", "both"):
                    data["buckets"][0]["bucket_public_access_block"] = None

                report = analyze_s3(data)

                self.assertEqual(report["summary"]["finding_count"], 0)
                self.assertEqual(report["summary"]["unknown_count"], 1)
                self.assertIsNone(
                    report["unknowns"][0][
                        "effective_restrict_public_buckets"
                    ]
                )

    def test_known_restriction_applies_when_other_level_is_unknown(self):
        for known_level in ("account", "bucket"):
            with self.subTest(known_level=known_level):
                data = self.make_data()

                if known_level == "account":
                    data["account_public_access_block"] = (
                        self.make_settings(restrict=True)
                    )
                    data["buckets"][0]["bucket_public_access_block"] = None
                else:
                    data["account_public_access_block"] = None
                    data["buckets"][0]["bucket_public_access_block"] = (
                        self.make_settings(restrict=True)
                    )

                report = analyze_s3(data)

                self.assertEqual(report["summary"]["restricted_count"], 1)
                self.assertEqual(report["summary"]["unknown_count"], 0)
                self.assertEqual(report["summary"]["finding_count"], 0)

    def test_unknown_policy_remains_unknown(self):
        data = self.make_data()
        data["buckets"][0]["policy_status"] = "unknown"
        data["account_public_access_block"] = self.make_settings(
            restrict=True
        )

        report = analyze_s3(data)

        self.assertEqual(report["summary"]["unknown_count"], 1)
        self.assertEqual(report["summary"]["restricted_count"], 0)
        self.assertEqual(report["summary"]["finding_count"], 0)

    def test_nonpublic_and_absent_policies_are_not_flagged(self):
        for status in ("nonpublic", "absent"):
            with self.subTest(status=status):
                data = self.make_data()
                data["buckets"][0]["policy_status"] = status

                report = analyze_s3(data)

                self.assertEqual(report["summary"]["not_flagged_count"], 1)
                self.assertEqual(report["summary"]["finding_count"], 0)
                self.assertEqual(report["summary"]["unknown_count"], 0)

    def test_invalid_or_missing_settings_are_rejected(self):
        for case in (
            "string_boolean",
            "numeric_boolean",
            "missing_flag",
            "missing_account_settings",
            "missing_bucket_settings",
            "invalid_policy_status",
        ):
            with self.subTest(case=case):
                data = self.make_data()
                bucket = data["buckets"][0]
                settings = bucket["bucket_public_access_block"]

                if case == "string_boolean":
                    settings["RestrictPublicBuckets"] = "false"
                elif case == "numeric_boolean":
                    settings["RestrictPublicBuckets"] = 0
                elif case == "missing_flag":
                    del settings["RestrictPublicBuckets"]
                elif case == "missing_account_settings":
                    del data["account_public_access_block"]
                elif case == "missing_bucket_settings":
                    del bucket["bucket_public_access_block"]
                else:
                    bucket["policy_status"] = "invalid"

                with self.assertRaises(ValueError):
                    analyze_s3(data)

    def test_duplicate_bucket_names_are_rejected(self):
        data = self.make_data()
        data["buckets"].append(dict(data["buckets"][0]))

        with self.assertRaisesRegex(ValueError, "중복"):
            analyze_s3(data)


if __name__ == "__main__":
    unittest.main()