import argparse
import json
from fnmatch import fnmatchcase
from pathlib import Path


ASSUME_ROLE_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)


def string_list(value, label):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise ValueError(f"{label}: 문자열 또는 문자열 배열이어야 합니다.")

    if not values or any(
        not isinstance(item, str) or not item.strip()
        for item in values
    ):
        raise ValueError(f"{label}: 비어 있지 않은 문자열이 필요합니다.")

    return values


def has_wildcard_principal(principal, label):
    if principal == "*":
        return True

    if not isinstance(principal, dict) or not principal:
        raise ValueError(
            f"{label}: Principal은 '*' 또는 비어 있지 않은 객체여야 합니다."
        )

    supported_types = {
        "AWS",
        "Service",
        "Federated",
        "CanonicalUser",
    }

    wildcard = False

    for principal_type, value in principal.items():
        if principal_type not in supported_types:
            raise ValueError(
                f"{label}: 지원하지 않는 Principal 유형입니다."
            )

        values = string_list(
            value,
            f"{label}의 Principal.{principal_type}",
        )

        if principal_type == "AWS" and "*" in values:
            wildcard = True

        if principal_type != "AWS" and "*" in values:
            raise ValueError(
                f"{label}: {principal_type}의 전체 와일드카드는 "
                "현재 분석 범위에서 지원하지 않습니다."
            )

    return wildcard


def analyze_trust_policies(data):
    if not isinstance(data, dict):
        raise ValueError("최상위 구조는 JSON 객체여야 합니다.")

    roles = data.get("roles")
    if not isinstance(roles, list):
        raise ValueError("roles는 배열이어야 합니다.")

    findings = []
    seen_names = set()

    for role_index, role in enumerate(roles, start=1):
        if not isinstance(role, dict):
            raise ValueError(f"역할 #{role_index}: JSON 객체여야 합니다.")

        name = role.get("role_name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"역할 #{role_index}: role_name이 필요합니다.")

        if name in seen_names:
            raise ValueError(f"중복된 역할 이름입니다: {name}")
        seen_names.add(name)

        policy = role.get("trust_policy")
        if not isinstance(policy, dict):
            raise ValueError(f"역할 {name}: trust_policy는 객체여야 합니다.")

        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]

        if not isinstance(statements, list) or not statements:
            raise ValueError(f"역할 {name}: 비어 있지 않은 Statement가 필요합니다.")

        for index, statement in enumerate(statements, start=1):
            label = f"역할 {name}, 구문 #{index}"

            if not isinstance(statement, dict):
                raise ValueError(f"{label}: JSON 객체여야 합니다.")

            if statement.get("Effect") not in ("Allow", "Deny"):
                raise ValueError(f"{label}: Effect는 Allow 또는 Deny여야 합니다.")

            for field in ("NotPrincipal", "NotAction"):
                if field in statement:
                    raise ValueError(
                        f"{label}: 현재 {field} 분석은 지원하지 않습니다."
                    )

            actions = string_list(
                statement.get("Action"),
                f"{label}의 Action",
            )
            wildcard = has_wildcard_principal(
                statement.get("Principal"),
                label,
            )

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
                        f"{label}: Condition 구조가 올바르지 않습니다."
                    )

            if statement["Effect"] != "Allow":
                continue

            allows_assumption = any(
                fnmatchcase(target, action.lower())
                for action in actions
                for target in ASSUME_ROLE_ACTIONS
            )

            if not wildcard or not allows_assumption:
                continue

            if has_condition:
                message = (
                    "전체 Principal을 지정한 역할 수임 허용 구문입니다. "
                    "접근 범위를 제한하는 조건의 적절성을 확인해야 합니다."
                )
            else:
                message = (
                    "조건 없이 전체 Principal을 지정한 "
                    "역할 수임 허용 구문입니다."
                )

            findings.append({
                "rule_id": "IAM006",
                "role_name": name,
                "statement": index,
                "sid": statement.get("Sid", "(없음)"),
                "has_condition": has_condition,
                "condition": condition if has_condition else None,
                "review_status": (
                    "condition_review"
                    if has_condition
                    else "unrestricted_principal"
                ),
                "message": message,
                "recommendation": (
                    "의도한 주체와 신뢰 범위를 확인하고, "
                    "명시적 Principal 또는 적절한 조건으로 제한하세요."
                ),
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="역할 신뢰 정책의 전체 Principal 허용을 점검합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="역할 신뢰 정책 JSON 파일",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        findings = analyze_trust_policies(data)

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] 신뢰 정책 분석 실패: {error}\n")

    print(f"분석한 역할 수: {len(data['roles'])}")
    print(f"검토 대상 탐지 건수: {len(findings)}")

    for finding in findings:
        status = (
            "조건 검토 필요"
            if finding["has_condition"]
            else "조건 없음"
        )
        print(
            f"\n[{finding['rule_id']}] "
            f"{finding['role_name']} / {status}"
        )
        print(f"구문 번호: {finding['statement']}")
        print(f"내용: {finding['message']}")

        if finding["has_condition"]:
            print(
                "조건: "
                + json.dumps(
                    finding["condition"],
                    ensure_ascii=False,
                )
            )

        print(f"개선: {finding['recommendation']}")

    print("\n참고: 전체 Principal을 허용하는 구문만 점검합니다.")
    print("조건 충족 여부와 명시적 거부 등은 종합 평가하지 않습니다.")
    print("탐지는 실제 역할 수임 성공이나 익명 접근 가능성을 뜻하지 않습니다.")
    print("특정 계정 신뢰, 서비스 주체 및 연동 주체의 적절성은 평가하지 않습니다.")


if __name__ == "__main__":
    main()