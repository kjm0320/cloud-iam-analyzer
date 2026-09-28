import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


def build_steps(profile):
    return [
        (
            "사용자 및 MFA 수집",
            [
                "collect_users.py",
                "--profile",
                profile,
            ],
        ),
        (
            "Access Key 정보 수집",
            [
                "collect_access_keys.py",
                "--profile",
                profile,
            ],
        ),
        (
            "IAM 정책 및 연결 정보 수집",
            [
                "collect_policies.py",
                "--profile",
                profile,
            ],
        ),
        (
            "실제 수집 데이터 통합 분석",
            ["scan_collected.py"],
        ),
        (
            "HTML 보고서 생성",
            ["html_collected_report.py"],
        ),
    ]


def run_pipeline(profile):
    steps = build_steps(profile)

    for index, (label, arguments) in enumerate(steps, start=1):
        script_path = PROJECT_ROOT / arguments[0]

        if not script_path.is_file():
            print(
                f"[ERROR] 필요한 파일이 없습니다: {script_path.name}",
                flush=True,
            )
            return 1

        command = [
            sys.executable,
            str(script_path),
            *arguments[1:],
        ]

        print(
            f"\n[{index}/{len(steps)}] {label}",
            flush=True,
        )

        try:
            result = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                check=False,
            )
        except OSError as error:
            print(
                f"[ERROR] 실행할 수 없습니다: {error}",
                flush=True,
            )
            return 1

        if result.returncode != 0:
            print(
                f"\n[ERROR] '{label}' 단계에서 중단했습니다.",
                flush=True,
            )
            print(
                "이후 단계는 실행하지 않았습니다.",
                flush=True,
            )
            print(
                "일부 수집 파일은 갱신되었을 수 있으며, "
                "기존 보고서는 이전 실행 결과일 수 있습니다.",
                flush=True,
            )
            print(
                "문제를 해결한 뒤 이 명령어를 처음부터 다시 실행하세요.",
                flush=True,
            )
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="AWS IAM 수집부터 HTML 보고서 생성까지 실행합니다."
    )
    parser.add_argument(
        "--profile",
        default="cloud-iam-analyzer",
        help="수집에 사용할 AWS CLI 프로필 이름",
    )
    args = parser.parse_args()

    print("AWS IAM 보안 점검을 시작합니다.", flush=True)
    print(
        "AWS 설정은 변경하지 않으며 결과는 비공개 경로에 저장합니다.",
        flush=True,
    )

    try:
        exit_code = run_pipeline(args.profile)
    except KeyboardInterrupt:
        print(
            "\n[중단] 사용자가 실행을 취소했습니다. "
            "기존 보고서는 이전 결과일 수 있습니다.",
            flush=True,
        )
        raise SystemExit(130)

    if exit_code != 0:
        raise SystemExit(exit_code)

    report_path = (
        PROJECT_ROOT
        / "reports"
        / "private"
        / "combined_report.html"
    )

    print("\n[완료] 수집·분석·HTML 생성이 모두 성공했습니다.")
    print(f"보고서 위치: {report_path}")
    print("실제 계정 정보가 포함된 보고서이므로 공개하지 마세요.")


if __name__ == "__main__":
    main()