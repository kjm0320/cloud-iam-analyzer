import unittest

from analyzer import analyze_policy


class TestAnalyzePolicy(unittest.TestCase):
    def test_full_access_is_detected(self):
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }

        findings = analyze_policy(policy)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM001")

    def test_limited_access_is_not_flagged(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-demo-bucket/*",
                }
            ]
        }

        self.assertEqual(analyze_policy(policy), [])

    def test_deny_is_not_flagged_as_allow(self):
        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "*", "Resource": "*"}
            ]
        }

        self.assertEqual(analyze_policy(policy), [])

    def test_single_statement_and_array_fields(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Action": ["*"],
                "Resource": ["*"],
            }
        }

        self.assertEqual(len(analyze_policy(policy)), 1)

    def test_condition_is_marked_for_review(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "aws:MultiFactorAuthPresent": "true"
                        }
                    },
                }
            ]
        }

        findings = analyze_policy(policy)

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["has_condition"])

class TestServiceWildcard(unittest.TestCase):
    def test_service_wildcard_is_detected(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            }]
        }

        findings = analyze_policy(policy)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM002")

    def test_service_wildcard_on_limited_resource(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": "arn:aws:s3:::example-demo-bucket/*",
            }]
        }

        findings = analyze_policy(policy)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM002")

    def test_denied_service_wildcard_is_not_flagged(self):
        policy = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
            }]
        }

        self.assertEqual(analyze_policy(policy), [])

if __name__ == "__main__":
    unittest.main()