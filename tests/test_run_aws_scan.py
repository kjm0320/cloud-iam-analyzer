import subprocess
import sys
import unittest
from unittest.mock import call, patch

from run_aws_scan import PROJECT_ROOT, run_pipeline


class TestRunAwsScan(unittest.TestCase):
    @patch("run_aws_scan.subprocess.run")
    @patch("run_aws_scan.Path.is_file", return_value=True)
    def test_all_steps_run_in_order(self, mock_is_file, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0
        )

        result = run_pipeline("test-profile")

        self.assertEqual(result, 0)

        expected_steps = [
            [
                "collect_users.py",
                "--profile",
                "test-profile",
            ],
            [
                "collect_access_keys.py",
                "--profile",
                "test-profile",
            ],
            [
                "collect_policies.py",
                "--profile",
                "test-profile",
            ],
            ["scan_collected.py"],
            ["html_collected_report.py"],
        ]

        expected_calls = [
            call(
                [
                    sys.executable,
                    str(PROJECT_ROOT / arguments[0]),
                    *arguments[1:],
                ],
                cwd=PROJECT_ROOT,
                check=False,
            )
            for arguments in expected_steps
        ]

        self.assertEqual(mock_run.call_args_list, expected_calls)

    @patch("run_aws_scan.subprocess.run")
    @patch("run_aws_scan.Path.is_file", return_value=True)
    def test_failure_stops_remaining_steps(self, mock_is_file, mock_run):
        for failed_step in range(5):
            with self.subTest(failed_step=failed_step + 1):
                mock_run.reset_mock()
                mock_run.side_effect = [
                    subprocess.CompletedProcess(args=[], returncode=0)
                    for _ in range(failed_step)
                ] + [
                    subprocess.CompletedProcess(args=[], returncode=1)
                ]

                result = run_pipeline("test-profile")

                self.assertEqual(result, 1)
                self.assertEqual(
                    mock_run.call_count,
                    failed_step + 1,
                )

    @patch("run_aws_scan.subprocess.run")
    @patch("run_aws_scan.Path.is_file", return_value=False)
    def test_missing_script_prevents_execution(
        self, mock_is_file, mock_run
    ):
        result = run_pipeline("test-profile")

        self.assertEqual(result, 1)
        mock_run.assert_not_called()

    @patch("run_aws_scan.subprocess.run")
    @patch("run_aws_scan.Path.is_file", return_value=True)
    def test_process_start_error_stops_pipeline(
        self, mock_is_file, mock_run
    ):
        mock_run.side_effect = OSError("테스트용 실행 오류")

        result = run_pipeline("test-profile")

        self.assertEqual(result, 1)
        self.assertEqual(mock_run.call_count, 1)


if __name__ == "__main__":
    unittest.main()