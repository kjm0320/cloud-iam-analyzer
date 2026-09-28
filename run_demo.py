import copy
import json
from collections import Counter
from pathlib import Path

from scan import build_report
from html_report import render_html


PROJECT_ROOT = Path(__file__).resolve().parent


def make_demo_inputs():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "UnrestrictedAccess",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Sid": "AllS3Actions",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            },
        ],
    }

    users = {
        "users": [{
            "user_name": "demo-user",
            "console_access": True,
            "mfa_enabled": False,
        }]
    }

    keys = {
        "collected_at": "2026-09-24T00:00:00Z",
        "access_keys": [
            {
                "user_name": "demo-user",
                "key_id": "DEMO_UNUSED_KEY",
                "status": "Active",
                "created_at": "2026-01-01T00:00:00Z",
                "usage_status": "used",
                "last_used_at": "2026-04-01T00:00:00Z",
            },
            {
                "user_name": "demo-user",
                "key_id": "DEMO_UNKNOWN_KEY",
                "status": "Active",
                "created_at": "2026-01-01T00:00:00Z",
                "usage_status": "unknown",
                "last_used_at": None,
            },
        ],
    }

    before = {
        "policy": policy,
        "users": users,
        "keys": keys,
    }
    after = copy.deepcopy(before)

    after["policy"]["Statement"] = [{
        "Sid": "ReadRequiredObjects",
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::demo-required-bucket/*",
    }]
    after["users"]["users"][0]["mfa_enabled"] = True

    for key in after["keys"]["access_keys"]:
        key["status"] = "Inactive"

    return before, after


def create_demo_report(inputs, stage):
    report = build_report(
        inputs["policy"],
        inputs["users"],
        inputs["keys"],
    )

    report["report_type"] = "synthetic_demo"
    report["demo_stage"] = stage
    report["sources"] = {
        "policy": f"{stage}/policy.json",
        "users": f"{stage}/users.json",
        "keys": f"{stage}/keys.json",
    }
    report["limitations"] = [
        "이 보고서는 공개용 가상 데이터로 생성한 데모입니다.",
        "실제 AWS에 접속하거나 계정 설정을 변경하지 않습니다.",
        "IAM001부터 IAM005까지 구현된 규칙만 적용합니다.",
        "실제 유효 권한, 정책 조건, 다른 정책의 거부는 종합 평가하지 않습니다.",
        "개선 후 키는 사용처 확인 후 불필요하다고 판단한 상황을 가정하여 비활성화했습니다.",
        "비활성 키는 오래된 키와 미사용 키 점검 대상에서 제외됩니다.",
        "판단 불가 감소는 사용 이력을 알아낸 결과가 아니라 키 비활성화의 결과입니다.",
        "탐지 0건이 전체 보안 상태의 안전함을 보장하지 않습니다.",
    ]

    return report


def rule_counts(report):
    return dict(Counter(
        finding["rule_id"]
        for finding in report["findings"]
    ))


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main():
    before_inputs, after_inputs = make_demo_inputs()
    before_report = create_demo_report(before_inputs, "before")
    after_report = create_demo_report(after_inputs, "after")

    expected_before = {
        "IAM001": 1,
        "IAM002": 1,
        "IAM003": 1,
        "IAM004": 2,
        "IAM005": 1,
    }

    if rule_counts(before_report) != expected_before:
        raise ValueError("개선 전 탐지 결과가 예상과 다릅니다.")

    if before_report["summary"]["unknown_count"] != 1:
        raise ValueError("개선 전 판단 불가 건수가 예상과 다릅니다.")

    if (
        after_report["findings"]
        or after_report["summary"]["unknown_count"] != 0
    ):
        raise ValueError("개선 후 분석 결과가 예상과 다릅니다.")

    # HTML 생성도 성공한 뒤 파일 저장을 시작합니다.
    html_reports = {
        "before": render_html(before_report),
        "after": render_html(after_report),
    }

    for stage, inputs, report in (
        ("before", before_inputs, before_report),
        ("after", after_inputs, after_report),
    ):
        sample_dir = PROJECT_ROOT / "samples" / "demo" / stage

        for name, data in inputs.items():
            write_json(sample_dir / f"{name}.json", data)

        report_dir = PROJECT_ROOT / "reports" / "demo"
        write_json(report_dir / f"{stage}.json", report)
        (report_dir / f"{stage}.html").write_text(
            html_reports[stage],
            encoding="utf-8",
        )

    comparison = {
        "scenario": "가상 IAM 설정 개선 전후 비교",
        "data_type": "synthetic",
        "before": {
            "summary": before_report["summary"],
            "rule_counts": rule_counts(before_report),
        },
        "after": {
            "summary": after_report["summary"],
            "rule_counts": rule_counts(after_report),
        },
        "changes": [
            "전체 작업 및 서비스 전체 작업 허용을 제거했습니다.",
            "필요한 샘플 버킷의 객체 읽기 권한만 남겼습니다.",
            "콘솔 사용자에 MFA를 설정한 상태로 변경했습니다.",
            "불필요하다고 판단한 가상 키 2개를 비활성화했습니다.",
        ],
        "limitations": after_report["limitations"],
    }
    write_json(
        PROJECT_ROOT / "reports" / "demo" / "comparison.json",
        comparison,
    )

    print("[성공] 공개용 가상 데이터와 비교 보고서를 생성했습니다.")
    print("개선 전: 탐지 6건 / 판단 불가 1건")
    print("개선 후: 탐지 0건 / 판단 불가 0건")
    print("개선 전 HTML: reports/demo/before.html")
    print("개선 후 HTML: reports/demo/after.html")
    print("비교 JSON: reports/demo/comparison.json")
    print("실제 AWS 설정은 변경하지 않았습니다.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"[ERROR] 데모 생성 실패: {error}")
        raise SystemExit(1)