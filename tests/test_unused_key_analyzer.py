import unittest

from unused_key_analyzer import analyze_unused_keys


class TestUnusedKeyAnalyzer(unittest.TestCase):
    def make_data(self, **changes):
        key = {
            "user_name": "demo-user",
            "key_id": "DEMO_TEST_KEY",
            "status": "Active",
            "created_at": "2025-12-01T00:00:00Z",
            "usage_status": "used",
            "last_used_at": "2026-01-01T00:00:00Z",
        }
        key.update(changes)

        return {
            "collected_at": "2026-04-01T00:00:00Z",
            "access_keys": [key],
        }

    def test_exactly_90_days_unused_is_detected(self):
        result = analyze_unused_keys(self.make_data())

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["rule_id"], "IAM005")
        self.assertEqual(result["findings"][0]["unused_days"], 90)
        self.assertEqual(result["unknowns"], [])

    def test_one_second_below_threshold_is_not_flagged(self):
        data = self.make_data(
            last_used_at="2026-01-01T00:00:01Z"
        )

        result = analyze_unused_keys(data)

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["unknowns"], [])

    def test_never_used_key_uses_creation_time(self):
        data = self.make_data(
            created_at="2026-01-01T00:00:00Z",
            usage_status="never_used",
            last_used_at=None,
        )

        result = analyze_unused_keys(data)

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["unused_days"], 90)

    def test_new_never_used_key_is_not_flagged(self):
        data = self.make_data(
            created_at="2026-03-31T00:00:00Z",
            usage_status="never_used",
            last_used_at=None,
        )

        self.assertEqual(
            analyze_unused_keys(data)["findings"], []
        )

    def test_unknown_usage_is_separate_from_findings(self):
        data = self.make_data(
            usage_status="unknown",
            last_used_at=None,
        )

        result = analyze_unused_keys(data)

        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["unknowns"]), 1)
        self.assertEqual(
            result["unknowns"][0]["key_id"], "DEMO_TEST_KEY"
        )

    def test_inactive_keys_are_skipped(self):
        for usage_status in ("used", "never_used", "unknown"):
            with self.subTest(usage_status=usage_status):
                data = self.make_data(
                    status="Inactive",
                    usage_status=usage_status,
                    last_used_at=(
                        "2026-01-01T00:00:00Z"
                        if usage_status == "used"
                        else None
                    ),
                )

                result = analyze_unused_keys(data)

                self.assertEqual(result["findings"], [])
                self.assertEqual(result["unknowns"], [])

    def test_last_used_outside_valid_range_is_rejected(self):
        for timestamp in (
            "2025-11-30T00:00:00Z",
            "2026-04-02T00:00:00Z",
        ):
            with self.subTest(timestamp=timestamp):
                data = self.make_data(last_used_at=timestamp)

                with self.assertRaisesRegex(ValueError, "사이"):
                    analyze_unused_keys(data)

    def test_inconsistent_usage_state_is_rejected(self):
        cases = [
            {"usage_status": "used", "last_used_at": None},
            {"usage_status": "never_used"},
            {"usage_status": "unknown"},
            {"usage_status": "invalid"},
        ]

        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    analyze_unused_keys(self.make_data(**changes))

    def test_missing_usage_fields_are_rejected(self):
        for field in ("usage_status", "last_used_at"):
            with self.subTest(field=field):
                data = self.make_data()
                del data["access_keys"][0][field]

                with self.assertRaisesRegex(ValueError, field):
                    analyze_unused_keys(data)

    def test_custom_threshold_is_used(self):
        result = analyze_unused_keys(
            self.make_data(), max_unused_days=91
        )

        self.assertEqual(result["findings"], [])

    def test_invalid_threshold_is_rejected(self):
        for value in (0, -1, True, 1.5, "90"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "정수"):
                    analyze_unused_keys(
                        self.make_data(),
                        max_unused_days=value,
                    )


if __name__ == "__main__":
    unittest.main()