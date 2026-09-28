import unittest

from trust_analyzer import analyze_trust_policies


class TestTrustAnalyzer(unittest.TestCase):
    def make_data(self, **changes):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }
        statement.update(changes)

        return {
            "roles": [{
                "role_name": "demo-role",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [statement],
                },
            }]
        }

    def test_unrestricted_principal_is_detected(self):
        findings = analyze_trust_policies(self.make_data())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM006")
        self.assertEqual(findings[0]["role_name"], "demo-role")
        self.assertFalse(findings[0]["has_condition"])
        self.assertEqual(
            findings[0]["review_status"],
            "unrestricted_principal",
        )

    def test_aws_principal_string_and_array_are_supported(self):
        for principal in (
            {"AWS": "*"},
            {"AWS": ["*"]},
        ):
            with self.subTest(principal=principal):
                findings = analyze_trust_policies(
                    self.make_data(Principal=principal)
                )

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["rule_id"], "IAM006")

    def test_condition_is_preserved_for_review(self):
        condition = {
            "StringEquals": {
                "aws:PrincipalOrgID": "o-example123"
            }
        }

        findings = analyze_trust_policies(
            self.make_data(Condition=condition)
        )

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["has_condition"])
        self.assertEqual(findings[0]["condition"], condition)
        self.assertEqual(
            findings[0]["review_status"],
            "condition_review",
        )

    def test_deny_is_not_flagged_as_allow(self):
        findings = analyze_trust_policies(
            self.make_data(Effect="Deny")
        )

        self.assertEqual(findings, [])

    def test_specific_principals_are_not_flagged(self):
        for principal in (
            {"Service": "ec2.amazonaws.com"},
            {
                "AWS": (
                    "arn:aws:iam::123456789012:role/demo-source"
                )
            },
        ):
            with self.subTest(principal=principal):
                findings = analyze_trust_policies(
                    self.make_data(Principal=principal)
                )

                self.assertEqual(findings, [])

    def test_action_matching_and_single_statement(self):
        for action, expected_count in (
            ("sts:AssumeRole", 1),
            ("STS:AssumeRole", 1),
            (["sts:AssumeRole"], 1),
            ("sts:AssumeRole*", 1),
            ("sts:*", 1),
            ("*", 1),
            ("sts:TagSession", 0),
        ):
            with self.subTest(action=action):
                data = self.make_data(Action=action)
                policy = data["roles"][0]["trust_policy"]

                # 単一
                policy["Statement"] = policy["Statement"][0]

                findings = analyze_trust_policies(data)

                self.assertEqual(len(findings), expected_count)

    def test_invalid_fields_are_rejected(self):
        cases = [
            {"Principal": None},
            {"Principal": {}},
            {"Principal": {"AWS": []}},
            {"Action": []},
            {"Effect": "allow"},
            {"Condition": {}},
            {"Condition": {"StringEquals": "invalid"}},
            {"NotAction": "sts:AssumeRole"},
            {"NotPrincipal": {"AWS": "*"}},
        ]

        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    analyze_trust_policies(
                        self.make_data(**changes)
                    )

    def test_duplicate_role_names_are_rejected(self):
        data = self.make_data()
        data["roles"].append(self.make_data()["roles"][0])

        with self.assertRaisesRegex(ValueError, "중복"):
            analyze_trust_policies(data)


if __name__ == "__main__":
    unittest.main()