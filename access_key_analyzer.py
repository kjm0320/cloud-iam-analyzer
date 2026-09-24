import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_timestamp(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: 날짜 문자열이 필요합니다.")

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        raise ValueError(
            f"{field}: 올바른 ISO 8601 날짜가 아닙니다."
        ) from None

    if timestamp.tzinfo is None:
        raise ValueError(f"{field}: 시간대 정보가 필요합니다.")

    return timestamp.astimezone(timezone.utc)


def analyze_access_keys(data, max_age_days=90):
    if type(max_age_days) is not int or max_age_days < 1:
        raise ValueError("점검 기준 일수는 1 이상의 정수여야 합니다.")

    if not isinstance(data, dict):
        raise ValueError("최상위 구조는 JSON 객체여야 합니다.")

    collected_at = parse_timestamp(
        data.get("collected_at"), "collected_at"
    )

    keys = data.get("access_keys")
    if not isinstance(keys, list):
        raise ValueError("access_keys는 배열이어야 합니다.")

    findings = []
    seen_ids = set()

    for index, key in enumerate(keys, start=1):
        if not isinstance(key, dict):
            raise ValueError(f"키 #{index}: JSON 객체여야 합니다.")

        for field in ("user_name", "key_id"):
            value = key.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"키 #{index}: {field}가 필요합니다.")

        key_id = key["key_id"]

        if key_id in seen_ids:
            raise ValueError(f"중복된 key_id입니다: {key_id}")
        seen_ids.add(key_id)

        if key.get("status") not in ("Active", "Inactive"):
            raise ValueError(
                f"키 {key_id}: status는 Active 또는 Inactive여야 합니다."
            )

        created_at = parse_timestamp(
            key.get("created_at"),
            f"키 {key_id}의 created_at",
        )

        if created_at > collected_at:
            raise ValueError(
                f"키 {key_id}: 생성 시각이 수집 시각보다 미래입니다."
            )

        age = collected_at - created_at

        if (
            key["status"] == "Active"
            and age >= timedelta(days=max_age_days)
        ):
            findings.append({
                "rule_id": "IAM004",
                "user_name": key["user_name"],
                "key_id": key_id,
                "age_days": age.days,
                "threshold_days": max_age_days,
                "message": (
                    f"생성 후 {age.days}일 지난 활성 Access Key입니다."
                ),
                "recommendation": (
                    "사용처와 필요성을 확인하고, "
                    "임시 자격 증명 전환 또는 키 교체를 검토하세요."
                ),
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="오래된 활성 Access Key를 점검합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="분석할 Access Key JSON 경로",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="검토 대상으로 표시할 키의 최소 경과 일수 (기본: 90)",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        parser.exit(1, f"[ERROR] 파일을 읽을 수 없습니다: {error}\n")

    try:
        findings = analyze_access_keys(data, args.max_age_days)
    except ValueError as error:
        parser.exit(1, f"[ERROR] {error}\n")

    print(f"분석 파일: {args.input}")
    print(f"수집 기준 시각: {data['collected_at']}")
    print(f"점검 기준: 생성 후 {args.max_age_days}일 이상")
    print(f"키 수: {len(data['access_keys'])}")
    print(f"탐지 건수: {len(findings)}")

    for finding in findings:
        print(
            f"\n[{finding['rule_id']}] "
            f"{finding['user_name']} / {finding['key_id']}"
        )
        print(f"내용: {finding['message']}")
        print(f"개선: {finding['recommendation']}")

    print("\n참고: 수집 시각을 기준으로 활성 키의 생성 후 경과 시간을 점검합니다.")
    print("키의 유출 여부나 마지막 사용 시각은 평가하지 않습니다.")
    print("키를 변경하거나 삭제하지 않습니다.")


if __name__ == "__main__":
    main()