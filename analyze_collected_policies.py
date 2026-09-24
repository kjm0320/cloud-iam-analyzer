import argparse
import json
from pathlib import Path
from urllib.parse import unquote

from analyzer import analyze_policy
from validation import validate_policy


def decode_document(document):
    if isinstance(document, dict):
        return document

    if isinstance(document, str):
        try:
            decoded = json.loads(document)
        except json.JSONDecodeError:
            decoded = json.loads(unquote(document))

        if isinstance(decoded, dict):
            return decoded

    raise ValueError("정책 문서는 JSON 객체여야 합니다.")


def analyze_collected_policies(data):
    if not isinstance(data, dict):
        raise ValueError("수집 데이터는 JSON 객체여야 합니다.")

    details = data.get("authorization_details")
    if not isinstance(details, dict):
        raise ValueError("authorization_details가 필요합니다.")

    for field in (
        "Policies",
        "UserDetailList",
        "GroupDetailList",
        "RoleDetailList",
    ):
        items = details.get(field)
        if (
            not isinstance(items, list)
            or not all(isinstance(item, dict) for item in items)
        ):
            raise ValueError(f"{field}는 객체 배열이어야 합니다.")

    findings = []
    skipped = []
    analyzed_count = 0
    candidate_count = 0

    def record_skip(context, reason):
        skipped.append({
            **context,
            "reason": reason,
        })

    def inspect_document(document, context):
        nonlocal analyzed_count

        try:
            policy = decode_document(document)
            validate_policy(policy)
            results = analyze_policy(policy)
        except ValueError as error:
            record_skip(context, str(error))
            return

        analyzed_count += 1

        for finding in results:
            findings.append({
                **finding,
                **context,
            })

    for policy in details["Policies"]:
        candidate_count += 1
        context = {
            "policy_type": "managed",
            "policy_name": policy.get("PolicyName", "(이름 없음)"),
            "policy_arn": policy.get("Arn", ""),
        }

        default_id = policy.get("DefaultVersionId")
        versions = policy.get("PolicyVersionList")

        if (
            not isinstance(default_id, str)
            or not default_id
            or not isinstance(versions, list)
            or not all(isinstance(item, dict) for item in versions)
        ):
            record_skip(context, "정책 기본 버전 정보가 올바르지 않습니다.")
            continue

        default_versions = [
            version
            for version in versions
            if version.get("VersionId") == default_id
            and version.get("IsDefaultVersion") is True
        ]

        if len(default_versions) != 1:
            record_skip(
                context,
                "현재 기본 버전 문서를 하나로 확인할 수 없습니다.",
            )
            continue

        context["version_id"] = default_id
        inspect_document(
            default_versions[0].get("Document"),
            context,
        )

    for entity_field, name_field, policy_field, owner_type in (
        ("UserDetailList", "UserName", "UserPolicyList", "user"),
        ("GroupDetailList", "GroupName", "GroupPolicyList", "group"),
        ("RoleDetailList", "RoleName", "RolePolicyList", "role"),
    ):
        for entity in details[entity_field]:
            inline_policies = entity.get(policy_field, [])

            if not isinstance(inline_policies, list):
                raise ValueError(f"{policy_field}는 배열이어야 합니다.")

            for policy in inline_policies:
                candidate_count += 1

                context = {
                    "policy_type": "inline",
                    "owner_type": owner_type,
                    "owner_name": entity.get(name_field, "(이름 없음)"),
                    "owner_arn": entity.get("Arn", ""),
                }

                if not isinstance(policy, dict):
                    record_skip(
                        context,
                        "인라인 정책 항목이 JSON 객체가 아닙니다.",
                    )
                    continue

                context["policy_name"] = policy.get(
                    "PolicyName", "(이름 없음)"
                )
                inspect_document(
                    policy.get("PolicyDocument"),
                    context,
                )

    return {
        "schema_version": "1.0",
        "source": "collected_iam_policies",
        "collected_at": data.get("collected_at"),
        "summary": {
            "candidate_policy_count": candidate_count,
            "analyzed_policy_count": analyzed_count,
            "skipped_policy_count": len(skipped),
            "finding_count": len(findings),
        },
        "findings": findings,
        "skipped_policies": skipped,
        "limitations": [
            "IAM001과 IAM002를 정책 문서별로 적용합니다.",
            "관리형 정책은 현재 기본 버전만 분석합니다.",
            "역할 신뢰 정책은 이번 분석 대상이 아닙니다.",
            "정책의 연결 여부와 권한 경계로 사용되는지에 따라 의미가 다릅니다.",
            "탐지 결과를 특정 사용자의 실제 유효 권한으로 해석하면 안 됩니다.",
            "명시적 거부, 조건, SCP, 권한 경계 등을 종합 평가하지 않습니다.",
            "분석 제외 정책은 안전 판정이 아닙니다.",
            "수집 데이터에 없는 정책은 평가하지 않습니다.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="수집한 IAM 정책을 문서별로 분석합니다."
    )
    project_root = Path(__file__).resolve().parent

    parser.add_argument(
        "--input",
        type=Path,
        default=project_root / "data" / "private" / "policies.json",
        help="collect_policies.py로 생성한 수집 파일",
    )
    args = parser.parse_args()

    output = (
        project_root
        / "reports"
        / "private"
        / "policy_analysis.json"
    )
    temporary = output.with_suffix(".json.tmp")

    try:
        if args.input.resolve() == output.resolve():
            raise ValueError("입력 파일과 출력 파일은 달라야 합니다.")

        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        report = analyze_collected_policies(data)
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
            f"[ERROR] 분석 실패: {error}\n"
            "기존 보고서가 있다면 이전 실행 결과일 수 있습니다.\n",
        )

    summary = report["summary"]
    print(f"분석 대상 정책 수: {summary['candidate_policy_count']}")
    print(f"분석 완료 정책 수: {summary['analyzed_policy_count']}")
    print(f"분석 제외 정책 수: {summary['skipped_policy_count']}")
    print(f"탐지 건수: {summary['finding_count']}")
    print(f"보고서 저장: {output}")
    print("탐지 결과는 정책 구문 검토 대상이며 실제 유효 권한 판정은 아닙니다.")


if __name__ == "__main__":
    main()