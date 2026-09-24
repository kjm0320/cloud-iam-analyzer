import unittest

from validation import validate_policy


class TestPolicyValidation(unittest.TestCase):
    def test_allow_and_deny_are_accepted(self):
        for effect in ("Allow", "Deny"):
            with self.subTest(effect=effect):
                policy = {
                    "Statement": [{
                        "Effect": effect,
                        "Action": "*",
                        "Resource": "*",
                    }]
                }

                validate_policy(policy)

    def test_missing_effect_is_rejected(self):
        policy = {
            "Statement": [{
                "Action": "*",
                "Resource": "*",
            }]
        }

        with self.assertRaisesRegex(ValueError, "Effect"):
            validate_policy(policy)

    def test_invalid_effect_is_rejected(self):
        for effect in ("allow", "ALLOW", "", None, 123):
            with self.subTest(effect=effect):
                policy = {
                    "Statement": [{
                        "Effect": effect,
                        "Action": "*",
                        "Resource": "*",
                    }]
                }

                with self.assertRaisesRegex(ValueError, "Effect"):
                    validate_policy(policy)


if __name__ == "__main__":
    unittest.main()