import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from account_analyzer import validate_users
from aws_identity import get_account_identity


def collect_users(iam):
    started_at = datetime.now(timezone.utc)
    users = []

    user_pages = iam.get_paginator("list_users")
    mfa_pages = iam.get_paginator("list_mfa_devices")

    for page in user_pages.paginate():
        for aws_user in page["Users"]:
            name = aws_user["UserName"]

            try:
                iam.get_login_profile(UserName=name)
                console_access = True
            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code == "NoSuchEntity":
                    console_access = False
                else:
                    raise

            device_count = 0
            for mfa_page in mfa_pages.paginate(UserName=name):
                device_count += len(mfa_page["MFADevices"])

            users.append({
                "user_name": name,
                "console_access": console_access,
                "mfa_enabled": device_count > 0,
            })

    users.sort(key=lambda user: user["user_name"])

    result = {
        "schema_version": "1.0",
        "source": "aws_iam",
        "collection_started_at": started_at.isoformat(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "users": users,
        "limitations": [
            "IAM 사용자만 수집하며 루트 계정과 SSO 사용자는 포함하지 않습니다.",
            "콘솔 비밀번호 존재 여부를 console_access로 표현합니다.",
            "다른 정책으로 콘솔 접근이 제한되는지는 평가하지 않습니다.",
            "MFA 장치 연결 여부만 확인하며 MFA 강제 여부는 평가하지 않습니다.",
            "여러 API를 순차 조회하므로 동일 순간의 스냅샷은 아닙니다.",
        ],
    }

    validate_users(result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="실제 AWS IAM 사용자와 MFA 설정을 수집합니다."
    )
    parser.add_argument(
        "--profile",
        default="cloud-iam-analyzer",
        help="사용할 AWS CLI 프로필 이름",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    output = project_root / "data" / "private" / "users.json"
    temporary = output.with_suffix(".json.tmp")

    try:
        session = boto3.Session(profile_name=args.profile)
        config = Config(
            connect_timeout=10,
            read_timeout=30,
            retries={
                "mode": "standard",
                "total_max_attempts": 3,
            },
        )

        sts = session.client(
            "sts",
            region_name=session.region_name or "ap-northeast-2",
            config=config,
        )
        identity = get_account_identity(sts)

        iam = session.client("iam", config=config)
        data = collect_users(iam)

        # 수집 전후 인증 주체가 바뀌었는지 확인합니다.
        final_identity = get_account_identity(sts)
        if identity != final_identity:
            raise ValueError(
                "수집 전후 인증 정보가 달라졌습니다. 다시 수집하세요."
            )

        data.update(identity)

        serialized = json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
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
    except (BotoCoreError, OSError, ValueError) as error:
        parser.exit(
            1,
            f"[ERROR] 수집 또는 저장 실패: {error}\n"
            "이번 실행 결과를 분석에 사용하지 마세요.\n",
        )

    masked_id = "*" * 8 + identity["account_id"][-4:]

    print(f"수집 계정: {masked_id}")
    print(f"수집한 IAM 사용자 수: {len(data['users'])}")
    print(f"저장 위치: {output}")
    print("루트 계정과 SSO 사용자는 이번 수집 대상이 아닙니다.")


if __name__ == "__main__":
    main()