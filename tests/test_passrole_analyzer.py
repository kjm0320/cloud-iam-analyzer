import unittest

from passrole_analyzer import analyze_passrole


class TestPassRoleAnalyzer(unittest.TestCase):
    def make_policy(self, **changes):
        statement = {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        }
        statement.update(changes)

        return {
            "Version": "2012-10-17",
            "Statement": [statement],
        }

    def test_all_roles_are_detected(self):
        findings = analyze_passrole(self.make_policy())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM008")
        self.assertEqual(findings[0]["resource_scope"], "all_roles")
        self.assertEqual(findings[0]["wildcard_resources"], ["*"])
        self.assertFalse(findings[0]["has_condition"])

    def test_role_patterns_and_conditions_are_preserved(self):
        condition = {
            "StringEquals": {
                "iam:PassedToService": "lambda.amazonaws.com"
            }
        }

        for resource in (
            "arn:aws:iam::123456789012:role/app-*",
            "arn:aws:iam::123456789012:role/app-?",
        ):
            with self.subTest(resource=resource):
                findings = analyze_passrole(
                    self.make_policy(
                        Resource=resource,
                        Condition=condition,
                    )
                )

                self.assertEqual(len(findings), 1)
                self.assertEqual(
                    findings[0]["resource_scope"], "role_pattern"
                )
                self.assertEqual(
                    findings[0]["wildcard_resources"], [resource]
                )
                self.assertTrue(findings[0]["has_condition"])
                self.assertEqual(findings[0]["condition"], condition)

    def test_specific_role_is_not_flagged(self):
        findings = analyze_passrole(
            self.make_policy(
                Resource=(
                    "arn:aws:iam::123456789012:role/demo-lambda-role"
                )
            )
        )

        self.assertEqual(findings, [])

    def test_action_matching(self):
        for action, expected_count in (
            ("iam:PassRole", 1),
            ("IAM:PASSROLE", 1),
            ("iam:*", 1),
            ("iam:Pass*", 1),
            ("iam:PassRol?", 1),
            ("*", 1),
            ("iam:GetRole", 0),
            ("iam:PassRol[e]", 0),
        ):
            with self.subTest(action=action):
                findings = analyze_passrole(
                    self.make_policy(Action=action)
                )

                self.assertEqual(len(findings), expected_count)

    def test_deny_is_not_flagged(self):
        findings = analyze_passrole(
            self.make_policy(Effect="Deny")
        )

        self.assertEqual(findings, [])

    def test_single_statement_and_array_fields(self):
        policy = self.make_policy(
            Action=["iam:GetRole", "iam:PassRole"],
            Resource=[
                "arn:aws:iam::123456789012:role/specific-role",
                "arn:aws:iam::123456789012:role/app-*",
                "arn:aws:iam::123456789012:role/app-*",
            ],
        )
        policy["Statement"] = policy["Statement"][0]

        findings = analyze_passrole(policy)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["matching_actions"], ["iam:PassRole"]
        )
        self.assertEqual(
            findings[0]["wildcard_resources"],
            ["arn:aws:iam::123456789012:role/app-*"],
        )

    def test_non_role_resource_is_not_flagged_as_role_scope(self):
        for resource in (
            "arn:aws:s3:::demo-bucket/*",
            "arn:aws:iam::123456789012:user/*",
        ):
            with self.subTest(resource=resource):
                findings = analyze_passrole(
                    self.make_policy(Resource=resource)
                )

                self.assertEqual(findings, [])

    def test_invalid_condition_is_rejected(self):
        for condition in (
            None,
            {},
            {"StringEquals": {}},
            {"StringEquals": "lambda.amazonaws.com"},
        ):
            with self.subTest(condition=condition):
                with self.assertRaisesRegex(ValueError, "Condition"):
                    analyze_passrole(
                        self.make_policy(Condition=condition)
                    )


if __name__ == "__main__":
    unittest.main()