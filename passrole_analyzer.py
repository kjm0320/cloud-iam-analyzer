import argparse
import json
import re
from pathlib import Path

from validation import validate_policy


def action_matches(pattern, action):
    # IAM 작업 이름의 대소문자를 구분하지 않습니다.
    # 와일드카드는 *와 ?만 처리합니다.
    expression = re.escape(pattern)
    expression = expression.replace(r"\*", ".*").replace(r"\?", ".")

    return re.fullmatch(
        expression,
        action,
        flags=re.IGNORECASE,
    ) is not None


def is_wildcard_role_resource(resource):
    if resource == "*":
        return True

    parts = resource.split(":", 5)

    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[2] != "iam"
        or not parts[5].startswith("role/")
    ):
        return False

    return "*" in resource or "?" in resource


def analyze_passrole(policy):
    validate_policy(policy)

    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]

    findings = []

    for index, statement in enumerate(statements, start=1):
        if statement["Effect"] != "Allow":
            continue

        actions = statement["Action"]
        resources = statement["Resource"]

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        matching_actions = sorted({
            action
            for action in actions
            if action_matches(action, "iam:PassRole")
        })

        if not matching_actions:
            continue

        wildcard_resources = sorted({
            resource
            for resource in resources
            if is_wildcard_role_resource(resource)
        })

        if not wildcard_resources:
            continue

        has_condition = "Condition" in statement
        condition = statement.get("Condition")

        if has_condition:
            if (
                not isinstance(condition, dict)
                or not condition
                or not all(
                    isinstance(value, dict) and value
                    for value in condition.values()
                )
            ):
                raise ValueError(
                    f"구문 #{index}: Condition 구조가 올바르지 않습니다."
                )

        scope = (
            "all_roles"
            if "*" in wildcard_resources
            else "role_pattern"
        )

        scope_message = (
            "전체 역할 범위"
            if scope == "all_roles"
            else "와일드카드가 포함된 역할 범위"
        )

        findings.append({
            "rule_id": "IAM008",
            "statement": index,
            "sid": statement.get("Sid", "(없음)"),
            "matching_actions": matching_actions,
            "wildcard_resources": wildcard_resources,
            "resource_scope": scope,
            "has_condition": has_condition,
            "condition": condition if has_condition else None,
            "message": (
                f"{scope_message}에 iam:PassRole을 허용하는 구문입니다."
            ),
            "recommendation": (
                "전달할 역할을 필요한 범위로 제한하고, "
                "iam:PassedToService 등 조건의 적절성을 검토하세요."
            ),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="iam:PassRole의 와일드카드 역할 범위를 점검합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="분석할 IAM 정책 JSON 파일",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            policy = json.load(file)

        findings = analyze_passrole(policy)

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] PassRole 분석 실패: {error}\n")

    print(f"분석 파일: {args.input}")
    print(f"검토 대상 탐지 건수: {len(findings)}")

    for finding in findings:
        print(
            f"\n[{finding['rule_id']}] "
            f"구문 #{finding['statement']} / Sid: {finding['sid']}"
        )
        print(f"내용: {finding['message']}")
        print(
            "허용 작업: "
            + ", ".join(finding["matching_actions"])
        )
        print(
            "검토할 역할 범위: "
            + ", ".join(finding["wildcard_resources"])
        )

        if finding["has_condition"]:
            print("검토 상태: 조건의 제한 효과 확인 필요")
            print(
                "조건: "
                + json.dumps(
                    finding["condition"],
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print("검토 상태: 해당 구문에 조건 없음")

        print(f"개선: {finding['recommendation']}")

    print("\n참고: 역할 범위의 와일드카드만 점검합니다.")
    print("정책 변수의 실제 값과 전체 IAM 문법은 검증하지 않습니다.")
    print("조건, 명시적 거부, 권한 경계, SCP는 종합 평가하지 않습니다.")
    print("특정 역할만 허용된 경우에도 그 역할의 권한은 별도 검토가 필요합니다.")
    print("서비스 작업 권한과 역할 신뢰 관계를 확인하지 않으므로")
    print("탐지 결과만으로 실제 권한 상승 가능 여부를 확정할 수 없습니다.")


if __name__ == "__main__":
    main()