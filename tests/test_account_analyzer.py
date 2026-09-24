import unittest

from account_analyzer import analyze_users


class TestAccountAnalyzer(unittest.TestCase):
    def make_user(self, **changes):
        user = {
            "user_name": "demo-user",
            "console_access": True,
            "mfa_enabled": False,
        }
        user.update(changes)
        return user

    def test_console_user_without_mfa_is_detected(self):
        data = {"users": [self.make_user()]}

        findings = analyze_users(data)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM003")
        self.assertEqual(findings[0]["user_name"], "demo-user")

    def test_console_user_with_mfa_is_not_flagged(self):
        data = {"users": [self.make_user(mfa_enabled=True)]}

        self.assertEqual(analyze_users(data), [])

    def test_user_without_console_access_is_not_flagged(self):
        data = {"users": [self.make_user(console_access=False)]}

        self.assertEqual(analyze_users(data), [])

    def test_missing_status_is_rejected(self):
        for field in ("console_access", "mfa_enabled"):
            with self.subTest(field=field):
                user = self.make_user()
                del user[field]

                with self.assertRaisesRegex(ValueError, field):
                    analyze_users({"users": [user]})

    def test_non_boolean_status_is_rejected(self):
        for field in ("console_access", "mfa_enabled"):
            for value in ("false", 0, 1, None):
                with self.subTest(field=field, value=value):
                    user = self.make_user(**{field: value})

                    with self.assertRaisesRegex(ValueError, field):
                        analyze_users({"users": [user]})

    def test_duplicate_user_names_are_rejected(self):
        data = {"users": [self.make_user(), self.make_user()]}

        with self.assertRaisesRegex(ValueError, "중복"):
            analyze_users(data)


if __name__ == "__main__":
    unittest.main()