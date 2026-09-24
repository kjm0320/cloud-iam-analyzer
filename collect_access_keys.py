import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from unused_key_analyzer import analyze_unused_keys


def format_timestamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("AWS 응답의 날짜 또는 시간대가 올바르지 않습니다.")

    return value.astimezone(timezone.utc).isoformat()


def collect_access_keys(iam):
    started_at = datetime.now(timezone.utc)
    keys = []

    user_pages = iam.get_paginator("list_users")
    key_pages = iam.get_paginator("list_access_keys")

    for user_page in user_pages.paginate():
        for user in user_page["Users"]:
            user_name = user["UserName"]

            for key_page in key_pages.paginate(UserName=user_name):
                for metadata in key_page["AccessKeyMetadata"]:
                    key_id = metadata["AccessKeyId"]

                    response = iam.get_access_key_last_used(
                        AccessKeyId=key_id
                    )
                    usage = response.get("AccessKeyLastUsed")

                    if not isinstance(usage, dict):
                        raise ValueError(
                            "AWS 응답에 키 사용 정보 구조가 없습니다."
                        )

                    last_used = usage.get("LastUsedDate")

                    if last_used is None:
                        usage_status = "unknown"
                        last_used_at = None
                    else:
                        usage_status = "used"
                        last_used_at = format_timestamp(last_used)

                    keys.append({
                        "user_name": user_name,
                        "key_id": key_id,
                        "status": metadata["Status"],
                        "created_at": format_timestamp(
                            metadata["CreateDate"]
                        ),
                        "usage_status": usage_status,
                        "last_used_at": last_used_at,
                    })

    keys.sort(
        key=lambda key: (key["user_name"], key["key_id"])
    )

    result = {
        "schema_version": "1.0",
        "source": "aws_iam",
        "collection_started_at": started_at.isoformat(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "access_keys": keys,
        "limitations": [
            "IAM 사용자의 키만 수집하며 루트 계정 키는 포함하지 않습니다.",
            "비밀 액세스 키 값은 조회하거나 저장하지 않습니다.",
            "마지막 사용 시각이 없으면 unknown으로 분류합니다.",
            "조회 오류는 미사용으로 해석하지 않고 수집을 중단합니다.",
            "여러 API를 순차 조회하므로 동일 순간의 스냅샷은 아닙니다.",
            "수집에 사용 중인 키의 사용 이력도 수집 작업으로 갱신될 수 있습니다.",
        ],
    }

    # 기존 분석기의 입력 검증을 통과한 데이터만 저장합니다.
    analyze_unused_keys(result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="실제 AWS IAM Access Key 메타데이터를 수집합니다."
    )
    parser.add_argument(
        "--profile",
        default="cloud-iam-analyzer",
        help="사용할 AWS CLI 프로필 이름",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    output = project_root / "data" / "private" / "access_keys.json"
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

        data = collect_access_keys(iam)

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
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
    except (BotoCoreError, OSError, ValueError, KeyError) as error:
        parser.exit(
            1,
            f"[ERROR] 수집 또는 저장 실패: {error}\n"
            "이번 실행 결과를 분석에 사용하지 마세요.\n",
        )

    unknown_count = sum(
        key["usage_status"] == "unknown"
        for key in data["access_keys"]
    )

    print(f"수집한 Access Key 수: {len(data['access_keys'])}")
    print(f"사용 시각 미확인 키 수: {unknown_count}")
    print(f"저장 위치: {output}")
    print("비밀 액세스 키 값은 수집하지 않았습니다.")


if __name__ == "__main__":
    main()