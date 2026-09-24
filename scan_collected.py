import json
from pathlib import Path

from account_analyzer import analyze_users
from access_key_analyzer import analyze_access_keys
from unused_key_analyzer import analyze_unused_keys
from analyze_collected_policies import analyze_collected_policies


def load_json(path):
    with path.open(encoding="utf-8-sig") as file:
        return json.load(file)


def build_collected_report(policies, users, keys):
    for name, data in (
        ("정책", policies),
        ("사용자", users),
        ("키", keys),
    ):
        if not isinstance(data, dict):
            raise ValueError(f"{name} 데이터는 JSON 객체여야 합니다.")

        if data.get("source") != "aws_iam":
            raise ValueError(
                f"{name} 데이터는 AWS 수집기로 생성한 파일이어야 합니다."
            )

        if not data.get("collected_at"):
            raise ValueError(f"{name} 데이터에 수집 시각이 없습니다.")

    policy_result = analyze_collected_policies(policies)
    user_findings = analyze_users(users)
    aged_key_findings = analyze_access_keys(keys)
    unused_result = analyze_unused_keys(keys)

    user_names = {
        user["user_name"]
        for user in users["users"]
    }

    policy_users = policies["authorization_details"]["UserDetailList"]
    policy_user_names = set()

    for user in policy_users:
        name = user.get("UserName")
        if not isinstance(name, str) or not name:
            raise ValueError(
                "정책 수집 데이터의 사용자 이름이 올바르지 않습니다."
            )
        policy_user_names.add(name)

    if user_names != policy_user_names:
        raise ValueError(
            "사용자 수집 파일과 정책 수집 파일의 사용자 목록이 다릅니다. "
            "세 수집기를 다시 실행해 주세요."
        )

    for key in keys["access_keys"]:
        if key["user_name"] not in user_names:
            raise ValueError(
                "키의 소유자가 사용자 수집 파일에 없습니다. "
                "세 수집기를 다시 실행해 주세요."
            )

    findings = [
        *policy_result["findings"],
        *user_findings,
        *aged_key_findings,
        *unused_result["findings"],
    ]

    policy_summary = policy_result["summary"]

    return {
        "schema_version": "1.0",
        "report_type": "aws_collected",
        "collection_times": {
            "policies": policies["collected_at"],
            "users": users["collected_at"],
            "keys": keys["collected_at"],
        },
        "key_data_collected_at": keys["collected_at"],
        "sources": {
            "policy": "policies.json",
            "users": "users.json",
            "keys": "access_keys.json",
        },
        "summary": {
            "finding_count": len(findings),
            "unknown_count": len(unused_result["unknowns"]),
            "user_count": len(users["users"]),
            "access_key_count": len(keys["access_keys"]),
            "candidate_policy_count": (
                policy_summary["candidate_policy_count"]
            ),
            "analyzed_policy_count": (
                policy_summary["analyzed_policy_count"]
            ),
            "skipped_policy_count": (
                policy_summary["skipped_policy_count"]
            ),
        },
        "findings": findings,
        "unknowns": unused_result["unknowns"],
        "skipped_policies": policy_result["skipped_policies"],
        "limitations": [
            "저장된 AWS 수집 파일을 분석하며 이번 실행에서 AWS에 접속하지 않습니다.",
            "파일별 수집 시각이 다르며 동일 순간의 계정 상태를 보장하지 않습니다.",
            "사용자 이름을 비교하지만 동일 AWS 계정의 데이터인지는 검증하지 않습니다.",
            "정책은 IAM001과 IAM002를 적용하며 실제 유효 권한은 계산하지 않습니다.",
            "역할 신뢰 정책, 리소스 정책, SCP는 이번 분석 대상이 아닙니다.",
            "루트 계정과 SSO 사용자는 사용자 및 키 점검 대상에 포함되지 않습니다.",
            "MFA는 장치 연결 여부를 점검하며 실제 사용 강제 여부는 평가하지 않습니다.",
            "키의 생성 후 경과 기간과 미사용 기간 기준은 각각 90일입니다.",
            "사용 정보 판단 불가 항목과 분석 제외 정책은 안전 판정이 아닙니다.",
            "탐지 0건이 계정 전체의 안전함을 의미하지는 않습니다.",
        ],
    }


def main():
    project_root = Path(__file__).resolve().parent
    private_data = project_root / "data" / "private"
    output = (
        project_root
        / "reports"
        / "private"
        / "combined_report.json"
    )
    temporary = output.with_suffix(".json.tmp")

    try:
        policies = load_json(private_data / "policies.json")
        users = load_json(private_data / "users.json")
        keys = load_json(private_data / "access_keys.json")

        report = build_collected_report(policies, users, keys)
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
        print(f"[ERROR] 통합 분석 실패: {error}")
        print("기존 보고서가 있다면 이전 실행 결과일 수 있습니다.")
        raise SystemExit(1)

    summary = report["summary"]
    print(f"분석한 사용자 수: {summary['user_count']}")
    print(f"분석한 키 수: {summary['access_key_count']}")
    print(f"분석 완료 정책 수: {summary['analyzed_policy_count']}")
    print(f"분석 제외 정책 수: {summary['skipped_policy_count']}")
    print(f"탐지 건수: {summary['finding_count']}")
    print(f"사용 정보 판단 불가 건수: {summary['unknown_count']}")
    print(f"보고서 저장: {output}")


if __name__ == "__main__":
    main()