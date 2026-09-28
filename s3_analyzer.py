import argparse
import json
from pathlib import Path


BLOCK_FIELDS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def validate_block_settings(settings, label):
    # null은 설정을 확인하지 못했다는 의미입니다.
    # 설정이 없는 것으로 확인된 경우에는 네 필드를 false로 입력합니다.
    if settings is None:
        return

    if not isinstance(settings, dict):
        raise ValueError(f"{label}: 객체 또는 null이어야 합니다.")

    for field in BLOCK_FIELDS:
        if type(settings.get(field)) is not bool:
            raise ValueError(
                f"{label}: {field}는 true 또는 false여야 합니다."
            )


def effective_restriction(account_settings, bucket_settings):
    values = [
        None if settings is None else settings["RestrictPublicBuckets"]
        for settings in (account_settings, bucket_settings)
    ]

    if True in values:
        return True

    if None in values:
        return None

    return False


def analyze_s3(data):
    if not isinstance(data, dict):
        raise ValueError("최상위 구조는 JSON 객체여야 합니다.")

    if "account_public_access_block" not in data:
        raise ValueError("account_public_access_block이 필요합니다.")

    account_settings = data["account_public_access_block"]
    validate_block_settings(account_settings, "계정 차단 설정")

    buckets = data.get("buckets")
    if not isinstance(buckets, list):
        raise ValueError("buckets는 배열이어야 합니다.")

    findings = []
    unknowns = []
    restricted = []
    not_flagged = []
    seen_names = set()

    for index, bucket in enumerate(buckets, start=1):
        if not isinstance(bucket, dict):
            raise ValueError(f"버킷 #{index}: JSON 객체여야 합니다.")

        name = bucket.get("bucket_name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"버킷 #{index}: bucket_name이 필요합니다.")

        if name in seen_names:
            raise ValueError(f"중복된 버킷 이름입니다: {name}")
        seen_names.add(name)

        policy_status = bucket.get("policy_status")
        if policy_status not in (
            "public",
            "nonpublic",
            "absent",
            "unknown",
        ):
            raise ValueError(
                f"버킷 {name}: policy_status는 "
                "public, nonpublic, absent, unknown 중 하나여야 합니다."
            )

        if "bucket_public_access_block" not in bucket:
            raise ValueError(
                f"버킷 {name}: bucket_public_access_block이 필요합니다."
            )

        bucket_settings = bucket["bucket_public_access_block"]
        validate_block_settings(
            bucket_settings,
            f"버킷 {name}의 차단 설정",
        )

        restriction = effective_restriction(
            account_settings,
            bucket_settings,
        )

        context = {
            "bucket_name": name,
            "policy_status": policy_status,
            "effective_restrict_public_buckets": restriction,
        }

        if policy_status == "unknown":
            unknowns.append({
                **context,
                "message": "버킷 정책의 공개 여부를 확인할 수 없습니다.",
            })
            continue

        if policy_status in ("nonpublic", "absent"):
            not_flagged.append({
                **context,
                "message": (
                    "입력상 정책이 비공개이거나 존재하지 않아 "
                    "이번 공개 정책 규칙에 해당하지 않습니다."
                ),
            })
            continue

        if restriction is True:
            restricted.append({
                **context,
                "message": (
                    "공개 정책이 있지만 계정 또는 버킷의 "
                    "RestrictPublicBuckets 설정이 적용되어 있습니다."
                ),
            })
        elif restriction is None:
            unknowns.append({
                **context,
                "message": (
                    "공개 정책이 있으나 차단 설정 정보가 부족하여 "
                    "접근 제한 적용 여부를 확인할 수 없습니다."
                ),
            })
        else:
            findings.append({
                **context,
                "rule_id": "IAM007",
                "message": (
                    "공개 정책이 있으며 계정과 버킷 모두 "
                    "RestrictPublicBuckets가 꺼져 있습니다."
                ),
                "recommendation": (
                    "의도한 공개 여부를 확인하고, 필요하지 않다면 "
                    "정책의 공개 허용을 제거하거나 "
                    "RestrictPublicBuckets 적용을 검토하세요."
                ),
            })

    return {
        "schema_version": "1.0",
        "summary": {
            "bucket_count": len(buckets),
            "finding_count": len(findings),
            "unknown_count": len(unknowns),
            "restricted_count": len(restricted),
            "not_flagged_count": len(not_flagged),
        },
        "findings": findings,
        "unknowns": unknowns,
        "restricted": restricted,
        "not_flagged": not_flagged,
        "limitations": [
            "입력된 정책 공개 상태와 계정·버킷 차단 설정만 분석합니다.",
            "BlockPublicPolicy만으로 기존 공개 정책의 접근이 제한된다고 판단하지 않습니다.",
            "ACL, 액세스 포인트, 조직 수준 통제 및 다른 접근 제한은 평가하지 않습니다.",
            "실제 객체에 접근하는 요청은 수행하지 않습니다.",
            "제한 설정 확인이나 탐지 없음이 버킷 전체의 안전함을 보장하지 않습니다.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="S3 공개 정책과 접근 제한 설정을 점검합니다."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="S3 공개 접근 설정 JSON 파일",
    )
    args = parser.parse_args()

    try:
        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        report = analyze_s3(data)

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] S3 분석 실패: {error}\n")

    summary = report["summary"]
    print(f"분석한 버킷 수: {summary['bucket_count']}")
    print(f"검토 대상 탐지 건수: {summary['finding_count']}")
    print(f"판단 불가 건수: {summary['unknown_count']}")
    print(f"공개 정책의 제한 설정 확인 건수: {summary['restricted_count']}")
    print(f"공개 정책 규칙에 해당하지 않는 건수: {summary['not_flagged_count']}")

    for group, label in (
        ("findings", "IAM007"),
        ("unknowns", "판단 불가"),
        ("restricted", "제한 설정 확인"),
        ("not_flagged", "규칙 해당 없음"),
    ):
        for item in report[group]:
            print(f"\n[{label}] {item['bucket_name']}")
            print(f"내용: {item['message']}")
            if "recommendation" in item:
                print(f"개선: {item['recommendation']}")

    print("\n분석 한계:")
    for limitation in report["limitations"]:
        print(f"- {limitation}")


if __name__ == "__main__":
    main()