import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


DETAIL_FIELDS = (
    "UserDetailList",
    "GroupDetailList",
    "RoleDetailList",
    "Policies",
)


def serialize_datetime(value):
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat()

    raise ValueError(
        f"저장할 수 없는 데이터 형식입니다: {type(value).__name__}"
    )


def collect_policies(iam):
    started_at = datetime.now(timezone.utc)
    details = {field: [] for field in DETAIL_FIELDS}
    page_count = 0

    paginator = iam.get_paginator(
        "get_account_authorization_details"
    )

    for page in paginator.paginate():
        page_count += 1

        for field in DETAIL_FIELDS:
            items = page.get(field, [])

            if not isinstance(items, list):
                raise ValueError(
                    f"AWS 응답의 {field}가 배열이 아닙니다."
                )

            if not all(isinstance(item, dict) for item in items):
                raise ValueError(
                    f"AWS 응답의 {field} 항목이 객체가 아닙니다."
                )

            details[field].extend(items)

    if page_count == 0:
        raise ValueError("AWS에서 수집 응답을 받지 못했습니다.")

    inline_count = 0
    for entity_field, policy_field in (
        ("UserDetailList", "UserPolicyList"),
        ("GroupDetailList", "GroupPolicyList"),
        ("RoleDetailList", "RolePolicyList"),
    ):
        for entity in details[entity_field]:
            policies = entity.get(policy_field, [])

            if not isinstance(policies, list):
                raise ValueError(
                    f"AWS 응답의 {policy_field}가 배열이 아닙니다."
                )

            inline_count += len(policies)

    return {
        "schema_version": "1.0",
        "source": "aws_iam",
        "collection_started_at": started_at.isoformat(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "user_count": len(details["UserDetailList"]),
            "group_count": len(details["GroupDetailList"]),
            "role_count": len(details["RoleDetailList"]),
            "managed_policy_count": len(details["Policies"]),
            "inline_policy_count": inline_count,
        },
        "authorization_details": details,
        "limitations": [
            "IAM 권한 구성 정보의 수집 결과이며 분석 보고서는 아닙니다.",
            "정책 문서와 연결 관계를 보존하며 실제 유효 권한은 계산하지 않습니다.",
            "여러 페이지를 순차 조회하므로 동일 순간의 스냅샷은 아닙니다.",
            "S3 버킷 정책과 Organizations의 SCP 등은 수집하지 않습니다.",
            "역할 신뢰 정책은 일반 권한 정책과 구분하여 분석해야 합니다.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="실제 AWS IAM 정책과 연결 정보를 수집합니다."
    )
    parser.add_argument(
        "--profile",
        default="cloud-iam-analyzer",
        help="사용할 AWS CLI 프로필 이름",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    output = project_root / "data" / "private" / "policies.json"
    temporary = output.with_suffix(".json.tmp")

    try:
        session = boto3.Session(profile_name=args.profile)
        iam = session.client(
            "iam",
            config=Config(
                connect_timeout=10,
                read_timeout=30,
                retries={
                    "mode": "standard",
                    "total_max_attempts": 3,
                },
            ),
        )

        data = collect_policies(iam)

        # 날짜를 변환하고 직렬화까지 성공한 뒤 파일을 기록합니다.
        serialized = json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            default=serialize_datetime,
        )

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            serialized + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)

    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        parser.exit(
            1,
            f"[ERROR] AWS 조회 실패: {error.operation_name} / {code}\n"
            "새 결과를 저장하지 않았습니다. "
            "기존 파일이 있다면 이전 수집 결과입니다.\n",
        )
    except (BotoCoreError, OSError, ValueError, TypeError) as error:
        parser.exit(
            1,
            f"[ERROR] 수집 또는 저장 실패: {error}\n"
            "이번 실행 결과를 분석에 사용하지 마세요.\n",
        )

    summary = data["summary"]
    print(f"사용자 수: {summary['user_count']}")
    print(f"그룹 수: {summary['group_count']}")
    print(f"역할 수: {summary['role_count']}")
    print(f"수집한 관리형 정책 수: {summary['managed_policy_count']}")
    print(f"수집한 인라인 정책 수: {summary['inline_policy_count']}")
    print(f"저장 위치: {output}")
    print("수집 결과에는 계정 정보가 포함되므로 공개하지 마세요.")


if __name__ == "__main__":
    main()