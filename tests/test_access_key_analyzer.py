import unittest

from access_key_analyzer import analyze_access_keys


class TestAccessKeyAnalyzer(unittest.TestCase):
    def make_data(self, **changes):
        key = {
            "user_name": "demo-user",
            "key_id": "DEMO_TEST_KEY",
            "status": "Active",
            "created_at": "2026-01-01T00:00:00Z",
        }
        key.update(changes)

        return {
            "collected_at": "2026-04-01T00:00:00Z",
            "access_keys": [key],
        }

    def test_exactly_90_days_is_detected(self):
        findings = analyze_access_keys(self.make_data())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IAM004")
        self.assertEqual(findings[0]["age_days"], 90)

    def test_one_second_below_threshold_is_not_flagged(self):
        data = self.make_data(
            created_at="2026-01-01T00:00:01Z"
        )

        self.assertEqual(analyze_access_keys(data), [])

    def test_old_inactive_key_is_not_flagged(self):
        data = self.make_data(status="Inactive")

        self.assertEqual(analyze_access_keys(data), [])

    def test_custom_threshold_is_used(self):
        data = self.make_data()

        self.assertEqual(
            analyze_access_keys(data, max_age_days=91),
            [],
        )
        self.assertEqual(
            len(analyze_access_keys(data, max_age_days=30)),
            1,
        )

    def test_future_creation_time_is_rejected(self):
        data = self.make_data(
            created_at="2026-04-02T00:00:00Z"
        )

        with self.assertRaisesRegex(ValueError, "미래"):
            analyze_access_keys(data)

    def test_invalid_timestamps_are_rejected(self):
        for field in ("collected_at", "created_at"):
            for value in ("not-a-date", "2026-01-01T00:00:00", None):
                with self.subTest(field=field, value=value):
                    data = self.make_data()

                    if field == "collected_at":
                        data[field] = value
                    else:
                        data["access_keys"][0][field] = value

                    with self.assertRaisesRegex(ValueError, field):
                        analyze_access_keys(data)

    def test_timezone_offsets_are_normalized(self):
        data = self.make_data(
            created_at="2026-01-01T09:00:00+09:00"
        )

        findings = analyze_access_keys(data)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["age_days"], 90)

    def test_invalid_threshold_is_rejected(self):
        for value in (0, -1, True, 1.5, "90"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "정수"):
                    analyze_access_keys(
                        self.make_data(),
                        max_age_days=value,
                    )

    def test_duplicate_key_ids_are_rejected(self):
        data = self.make_data()
        data["access_keys"].append(
            dict(data["access_keys"][0])
        )

        with self.assertRaisesRegex(ValueError, "중복"):
            analyze_access_keys(data)

    def test_invalid_status_is_rejected(self):
        data = self.make_data(status="active")

        with self.assertRaisesRegex(ValueError, "status"):
            analyze_access_keys(data)


if __name__ == "__main__":
    unittest.main()