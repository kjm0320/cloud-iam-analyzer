import argparse
import json
from pathlib import Path


def analyze_policy(policy):
    findings = []
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements, start=1):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            findings.append({
                "rule_id": "IAM001",
                "statement": index,
                "sid": statement.get("Sid", "(없음)"),
                "message": "모든 작업과 모든 리소스를 허용하는 구문",
                "has_condition": "Condition" in statement,
            })

        service_wildcards = sorted({
            action
            for action in actions
            if action.endswith(":*")
            and action.count(":") == 1
            and action.split(":")[0]
        })

        if service_wildcards:
            findings.append({
                "rule_id": "IAM002",
                "statement": index,
                "sid": statement.get("Sid", "(없음)"),
                "message": (
                    "서비스의 모든 작업을 허용하는 구문: "
                    + ", ".join(service_wildcards)
                ),
                "has_condition": "Condition" in statement,
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="AWS IAM 정책의 보안 위험 후보를 분석합니다."
    )
    parser.add_argument(
        "policy",
        type=Path,
        help="분석할 정책 JSON 경로",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="분석 결과를 저장할 JSON 파일 경로",
    )
    args = parser.parse_args()

    try:
        with args.policy.open(encoding="utf-8-sig") as file:
            policy = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        parser.exit(
            1,
            f"[ERROR] 파일을 읽을 수 없습니다: {error}\n",
        )

    if not isinstance(policy, dict):
        parser.exit(
            1,
            "[ERROR] 정책의 최상위 구조는 JSON 객체여야 합니다.\n",
        )

    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]

    if (
        not isinstance(statements, list)
        or not statements
        or not all(isinstance(item, dict) for item in statements)
    ):
        parser.exit(
            1,
            "[ERROR] Statement는 객체 또는 비어 있지 않은 객체 배열이어야 합니다.\n",
        )

    for statement in statements:
        for field in ("Action", "Resource"):
            value = statement.get(field, [])
            if not (
                isinstance(value, str)
                or (
                    isinstance(value, list)
                    and all(isinstance(item, str) for item in value)
                )
            ):
                parser.exit(
                    1,
                    f"[ERROR] {field}는 문자열 또는 문자열 배열이어야 합니다.\n",
                )

    findings = analyze_policy(policy)

    if args.output:
        if args.output.resolve() == args.policy.resolve():
            parser.exit(
                1,
                "[ERROR] 출력 경로는 입력 정책 파일과 달라야 합니다.\n",
            )

        report = {
            "schema_version": "1.0",
            "source": args.policy.name,
            "finding_count": len(findings),
            "findings": findings,
            "limitations": [
                "IAM001과 IAM002 규칙만 적용합니다.",
                "실제 유효 권한과 조건 충족 여부는 평가하지 않습니다.",
                "탐지 0건이 안전함을 의미하지는 않습니다.",
            ],
        }

        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open(mode="w", encoding="utf-8") as file:
                json.dump(report, file, ensure_ascii=False, indent=2)
                file.write("\n")
        except OSError as error:
            parser.exit(
                1,
                f"[ERROR] 보고서를 저장할 수 없습니다: {error}\n",
            )

        print(f"보고서 저장: {args.output}")

    print(f"분석 파일: {args.policy}")
    print(f"탐지 건수: {len(findings)}")

    for finding in findings:
        print(
            f"\n[{finding['rule_id']}] "
            f"Statement #{finding['statement']} / Sid: {finding['sid']}"
        )
        print(f"내용: {finding['message']}")
        print("개선: 필요한 작업과 리소스로 허용 범위를 제한하세요.")
        if finding["has_condition"]:
            print("검토: Condition이 있으므로 적용 조건을 확인하세요.")

    print("\n참고: 현재는 전체 권한 및 서비스 전체 작업 허용 구문을 탐지합니다.")
    print("실제 유효 권한, 다른 정책의 Deny, 조건 충족 여부는 평가하지 않습니다.")
    print("탐지 0건이 안전함을 의미하지는 않습니다.")


if __name__ == "__main__":
    main()