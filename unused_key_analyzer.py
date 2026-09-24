import argparse
import json
from datetime import timedelta
from pathlib import Path

from access_key_analyzer import analyze_access_keys, parse_timestamp


def analyze_unused_keys(data, max_unused_days=90):
    if type(max_unused_days) is not int or max_unused_days < 1:
        raise ValueError("미사용 기준 일수는 1 이상의 정수여야 합니다.")

    # 기존 검증을 재사용합니다. IAM004 탐지 결과는 사용하지 않습니다.
    analyze_access_keys(data)

    collected_at = parse_timestamp(
        data["collected_at"], "collected_at"
    )
    findings = []
    unknowns = []

    for key in data["access_keys"]:
        key_id = key["key_id"]
        usage_status = key.get("usage_status")

        if usage_status not in ("used", "never_used", "unknown"):
            raise ValueError(
                f"키 {key_id}: usage_status는 "
                "used, never_used, unknown 중 하나여야 합니다."
            )

        if "last_used_at" not in key:
            raise ValueError(
                f"키 {key_id}: last_used_at 필드가 필요합니다."
            )

        created_at = parse_timestamp(
            key["created_at"], f"키 {key_id}의 created_at"
        )

        if usage_status == "used":
            reference_time = parse_timestamp(
                key["last_used_at"],
                f"키 {key_id}의 last_used_at",
            )

            if not created_at <= reference_time <= collected_at:
                raise ValueError(
                    f"키 {key_id}: 마지막 사용 시각은 "
                    "생성 시각과 수집 시각 사이여야 합니다."
                )
        else:
            if key["last_used_at"] is not None:
                raise ValueError(
                    f"키 {key_id}: {usage_status} 상태에서는 "
                    "last_used_at이 null이어야 합니다."
                )

            reference_time = created_at

        if key["status"] != "Active":
            continue

        if usage_status == "unknown":
            unknowns.append({
                "user_name": key["user_name"],
                "key_id": key_id,
                "message": "사용 정보를 확인할 수 없어 미사용 여부를 판단할 수 없습니다.",
            })
            continue

        unused_time = collected_at - reference_time

        if unused_time >= timedelta(days=max_unused_days):
            findings.append({
                "rule_id": "IAM005",
                "user_name": key["user_name"],
                "key_id": key_id,
                "unused_days": unused_time.days,
                "threshold_days": max_unused_days,
                "usage_status": usage_status,
                "message": (
                    f"{unused_time.days}일 동안 사용되지 않은 활성 키입니다."
                ),
                "recommendation": (
                    "사용처와 의존성을 확인한 뒤 "
                    "불필요한 키의 비활성화를 검토하세요."
                ),
            })

    return {"findings": findings, "unknowns": unknowns}


def main():
    parser = argparse.ArgumentParser(
        description="장기간 미사용인 활성 Access Key를 점검합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="사용 이력이 포함된 Access Key JSON 경로",
    )
    parser.add_argument(
        "--max-unused-days",
        type=int,
        default=90,
        help="미사용 점검 기준 일수 (기본: 90)",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        parser.exit(1, f"[ERROR] 파일을 읽을 수 없습니다: {error}\n")

    try:
        result = analyze_unused_keys(data, args.max_unused_days)
    except ValueError as error:
        parser.exit(1, f"[ERROR] {error}\n")

    print(f"분석 파일: {args.input}")
    print(f"수집 기준 시각: {data['collected_at']}")
    print(f"미사용 기준: {args.max_unused_days}일 이상")
    print(f"탐지 건수: {len(result['findings'])}")
    print(f"판단 불가 건수: {len(result['unknowns'])}")

    for finding in result["findings"]:
        print(
            f"\n[{finding['rule_id']}] "
            f"{finding['user_name']} / {finding['key_id']}"
        )
        print(f"내용: {finding['message']}")
        print(f"개선: {finding['recommendation']}")

    for unknown in result["unknowns"]:
        print(
            f"\n[판단 불가] "
            f"{unknown['user_name']} / {unknown['key_id']}"
        )
        print(f"내용: {unknown['message']}")

    print("\n참고: 입력 데이터의 사용 상태와 시각을 기준으로 분석합니다.")
    print("실제 키를 변경하거나 삭제하지 않습니다.")


if __name__ == "__main__":
    main()