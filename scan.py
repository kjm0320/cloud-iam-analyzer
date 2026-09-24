import argparse
import json
from pathlib import Path

from analyzer import analyze_policy
from validation import validate_policy
from account_analyzer import analyze_users
from access_key_analyzer import analyze_access_keys
from unused_key_analyzer import analyze_unused_keys


def load_json(path):
    with path.open(encoding="utf-8-sig") as file:
        return json.load(file)


def build_report(policy, users, keys):
    validate_policy(policy)

    findings = []
    findings.extend(analyze_policy(policy))
    findings.extend(analyze_users(users))
    findings.extend(analyze_access_keys(keys))

    unused_result = analyze_unused_keys(keys)
    findings.extend(unused_result["findings"])

    return {
        "schema_version": "1.0",
        "key_data_collected_at": keys["collected_at"],
        "summary": {
            "finding_count": len(findings),
            "unknown_count": len(unused_result["unknowns"]),
            "user_count": len(users["users"]),
            "access_key_count": len(keys["access_keys"]),
        },
        "findings": findings,
        "unknowns": unused_result["unknowns"],
        "limitations": [
            "제공된 입력 데이터만 분석하며 실제 AWS에 연결하지 않습니다.",
            "실제 유효 권한과 정책 조건 충족 여부는 평가하지 않습니다.",
            "키의 생성 후 경과 기간과 미사용 기간 기준은 각각 90일입니다.",
            "사용 정보를 모르는 활성 키는 판단 불가로 분리합니다.",
            "탐지 0건이 안전함을 의미하지는 않습니다.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="IAM 정책·사용자·Access Key 통합 분석기"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--users", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    input_paths = [args.policy, args.users, args.keys]

    try:
        output_path = args.output.resolve()

        if any(
            output_path == path.resolve()
            for path in input_paths
        ):
            raise ValueError("출력 경로는 입력 파일과 달라야 합니다.")

        policy = load_json(args.policy)
        users = load_json(args.users)
        keys = load_json(args.keys)

        report = build_report(policy, users, keys)
        report["sources"] = {
            "policy": args.policy.name,
            "users": args.users.name,
            "keys": args.keys.name,
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open(mode="w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)
            file.write("\n")

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] {error}\n")

    summary = report["summary"]
    print(f"탐지 건수: {summary['finding_count']}")
    print(f"판단 불가 건수: {summary['unknown_count']}")

    for finding in report["findings"]:
        target = finding.get("user_name", "입력 정책")
        if "key_id" in finding:
            target += f" / {finding['key_id']}"
        print(f"[{finding['rule_id']}] {target}")
        print(f"  {finding['message']}")

    for unknown in report["unknowns"]:
        print(
            f"[판단 불가] "
            f"{unknown['user_name']} / {unknown['key_id']}"
        )

    print(f"\n보고서 저장: {args.output}")
    print("탐지 건수는 영향받는 사용자나 키의 고유 개수가 아닙니다.")
    print("동일한 키가 여러 규칙에 해당하면 각각 집계됩니다.")


if __name__ == "__main__":
    main()