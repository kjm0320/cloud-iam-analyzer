import argparse
import json
from pathlib import Path


def validate_users(data):
    if not isinstance(data, dict):
        raise ValueError("최상위 구조는 JSON 객체여야 합니다.")

    users = data.get("users")
    if not isinstance(users, list):
        raise ValueError("users는 배열이어야 합니다.")

    names = set()

    for index, user in enumerate(users, start=1):
        if not isinstance(user, dict):
            raise ValueError(f"사용자 #{index}: JSON 객체여야 합니다.")

        name = user.get("user_name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"사용자 #{index}: user_name이 필요합니다.")

        if name in names:
            raise ValueError(f"중복된 user_name입니다: {name}")
        names.add(name)

        for field in ("console_access", "mfa_enabled"):
            if not isinstance(user.get(field), bool):
                raise ValueError(
                    f"사용자 {name}: {field}는 true 또는 false여야 합니다."
                )


def analyze_users(data):
    validate_users(data)
    findings = []

    for user in data["users"]:
        if user["console_access"] and not user["mfa_enabled"]:
            findings.append({
                "rule_id": "IAM003",
                "user_name": user["user_name"],
                "message": "콘솔 로그인이 가능하지만 MFA가 설정되어 있지 않습니다.",
                "recommendation": "해당 IAM 사용자에 MFA를 설정하세요.",
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="IAM 사용자 데이터에서 보안 위험 후보를 분석합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="분석할 사용자 JSON 파일 경로",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        parser.exit(1, f"[ERROR] 파일을 읽을 수 없습니다: {error}\n")

    try:
        findings = analyze_users(data)
    except ValueError as error:
        parser.exit(1, f"[ERROR] {error}\n")

    print(f"분석 파일: {args.input}")
    print(f"사용자 수: {len(data['users'])}")
    print(f"탐지 건수: {len(findings)}")

    for finding in findings:
        print(f"\n[{finding['rule_id']}] {finding['user_name']}")
        print(f"내용: {finding['message']}")
        print(f"개선: {finding['recommendation']}")

    print("\n참고: 제공된 IAM 사용자 데이터만 분석합니다.")
    print("MFA 상태가 누락되면 미설정으로 추측하지 않고 오류로 처리합니다.")
    print("SSO 사용자, 루트 계정 및 실제 로그인 시 MFA 강제 여부는 평가하지 않습니다.")
    print("탐지 0건이 계정 전체의 안전함을 의미하지는 않습니다.")


if __name__ == "__main__":
    main()