import argparse
import json
from pathlib import Path

from analyze_collected_policies import decode_document
from trust_analyzer import analyze_trust_policies


def analyze_collected_trust(data):
    if not isinstance(data, dict):
        raise ValueError("수집 데이터는 JSON 객체여야 합니다.")

    details = data.get("authorization_details")
    if not isinstance(details, dict):
        raise ValueError("authorization_details가 필요합니다.")

    roles = details.get("RoleDetailList")
    if (
        not isinstance(roles, list)
        or not all(isinstance(role, dict) for role in roles)
    ):
        raise ValueError("RoleDetailList는 객체 배열이어야 합니다.")

    findings = []
    skipped = []
    analyzed_count = 0
    seen_names = set()

    for index, role in enumerate(roles, start=1):
        name = role.get("RoleName")
        arn = role.get("Arn", "")

        if not isinstance(name, str) or not name.strip():
            skipped.append({
                "role_name": f"(역할 #{index}: 이름 없음)",
                "role_arn": arn,
                "reason": "역할 이름이 없거나 올바르지 않습니다.",
            })
            continue

        if name in seen_names:
            raise ValueError(f"중복된 역할 이름입니다: {name}")
        seen_names.add(name)

        try:
            document = decode_document(
                role.get("AssumeRolePolicyDocument")
            )

            results = analyze_trust_policies({
                "roles": [{
                    "role_name": name,
                    "trust_policy": document,
                }]
            })

        except ValueError as error:
            skipped.append({
                "role_name": name,
                "role_arn": arn,
                "reason": str(error),
            })
            continue

        analyzed_count += 1

        for finding in results:
            findings.append({
                **finding,
                "role_arn": arn,
            })

    return {
        "schema_version": "1.0",
        "report_type": "collected_trust_analysis",
        "account_id": data.get("account_id"),
        "partition": data.get("partition"),
        "collected_at": data.get("collected_at"),
        "summary": {
            "role_count": len(roles),
            "analyzed_role_count": analyzed_count,
            "skipped_role_count": len(skipped),
            "finding_count": len(findings),
            "condition_review_count": sum(
                finding["has_condition"]
                for finding in findings
            ),
        },
        "findings": findings,
        "skipped_roles": skipped,
        "limitations": [
            "저장된 정책 수집 파일만 분석하며 AWS에 다시 접속하지 않습니다.",
            "IAM006은 역할 수임을 허용하는 전체 Principal 구문을 점검합니다.",
            "조건이 있는 탐지는 조건의 적절성을 확인해야 하는 검토 대상입니다.",
            "조건 충족 여부와 명시적 거부 등은 종합 평가하지 않습니다.",
            "실제 역할 수임 성공이나 익명 접근 가능성을 판정하지 않습니다.",
            "특정 계정 신뢰, 서비스 주체 및 연동 주체의 적절성은 평가하지 않습니다.",
            "분석 제외 역할은 안전 판정이 아닙니다.",
            "탐지 0건이 역할 신뢰 설정 전체의 안전함을 보장하지 않습니다.",
        ],
    }


def main():
    project_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="수집된 실제 역할 신뢰 정책을 분석합니다."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=project_root / "data" / "private" / "policies.json",
    )
    args = parser.parse_args()

    output = (
        project_root
        / "reports"
        / "private"
        / "trust_analysis.json"
    )
    temporary = output.with_suffix(".json.tmp")

    try:
        if args.input.resolve() == output.resolve():
            raise ValueError("입력 파일과 출력 파일은 달라야 합니다.")

        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        report = analyze_collected_trust(data)
        serialized = json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        )

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            serialized + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)

    except (OSError, ValueError) as error:
        parser.exit(
            1,
            f"[ERROR] 신뢰 정책 분석 실패: {error}\n"
            "기존 보고서가 있다면 이전 실행 결과일 수 있습니다.\n",
        )

    summary = report["summary"]
    print(f"수집된 역할 수: {summary['role_count']}")
    print(f"분석 완료 역할 수: {summary['analyzed_role_count']}")
    print(f"분석 제외 역할 수: {summary['skipped_role_count']}")
    print(f"검토 대상 탐지 건수: {summary['finding_count']}")
    print(f"조건 검토 필요 건수: {summary['condition_review_count']}")
    print(f"보고서 저장: {output}")


if __name__ == "__main__":
    main()