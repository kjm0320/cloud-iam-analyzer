import unittest

from validation import validate_policy


class TestPolicyValidation(unittest.TestCase):
    def make_statement(self):
        return {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }

    def test_allow_and_deny_are_accepted(self):
        for effect in ("Allow", "Deny"):
            with self.subTest(effect=effect):
                statement = self.make_statement()
                statement["Effect"] = effect
                validate_policy({"Statement": [statement]})

    def test_missing_effect_is_rejected(self):
        statement = self.make_statement()
        del statement["Effect"]

        with self.assertRaisesRegex(ValueError, "Effect"):
            validate_policy({"Statement": [statement]})

    def test_invalid_effect_is_rejected(self):
        for effect in ("allow", "ALLOW", "", None, 123):
            with self.subTest(effect=effect):
                statement = self.make_statement()
                statement["Effect"] = effect

                with self.assertRaisesRegex(ValueError, "Effect"):
                    validate_policy({"Statement": [statement]})

    def test_missing_action_or_resource_is_rejected(self):
        for field in ("Action", "Resource"):
            with self.subTest(field=field):
                statement = self.make_statement()
                del statement[field]

                with self.assertRaisesRegex(ValueError, field):
                    validate_policy({"Statement": [statement]})

    def test_empty_values_are_rejected(self):
        for field in ("Action", "Resource"):
            for value in ("", "   ", [], [""], ["*", ""]):
                with self.subTest(field=field, value=value):
                    statement = self.make_statement()
                    statement[field] = value

                    with self.assertRaisesRegex(ValueError, field):
                        validate_policy({"Statement": [statement]})

    def test_invalid_field_types_are_rejected(self):
        for field in ("Action", "Resource"):
            for value in (None, 123, True, {}, [123], ["*", None]):
                with self.subTest(field=field, value=value):
                    statement = self.make_statement()
                    statement[field] = value

                    with self.assertRaisesRegex(ValueError, field):
                        validate_policy({"Statement": [statement]})

    def test_string_arrays_are_accepted(self):
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::example-demo-bucket/*"],
        }

        validate_policy({"Statement": [statement]})

    def test_unsupported_fields_are_reported(self):
        for field, replacement in (
            ("Action", "NotAction"),
            ("Resource", "NotResource"),
        ):
            with self.subTest(field=replacement):
                statement = self.make_statement()
                del statement[field]
                statement[replacement] = "*"

                with self.assertRaisesRegex(
                    ValueError,
                    rf"{replacement} 분석을 지원하지 않습니다",
                ):
                    validate_policy({"Statement": [statement]})


if __name__ == "__main__":
    unittest.main()