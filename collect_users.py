import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from account_analyzer import validate_users


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

            # 여기서 사용자가 삭제되거나 조회 권한이 없으면 중단합니다.
            # 오류를 MFA 미설정으로 취급하지 않습니다.
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

        data = collect_users(iam)

        # 전체 수집과 검증에 성공한 뒤에만 결과를 저장합니다.
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)

    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        operation = error.operation_name
        parser.exit(
            1,
            f"[ERROR] AWS 조회 실패: {operation} / {code}\n"
            "새 결과를 저장하지 않았습니다. "
            "기존 파일이 있다면 이전 수집 결과입니다.\n",
        )
    except (BotoCoreError, OSError, ValueError) as error:
        parser.exit(
            1,
            f"[ERROR] 수집 또는 저장 실패: {error}\n"
            "이번 실행 결과를 분석에 사용하지 마세요.\n",
        )

    print(f"수집한 IAM 사용자 수: {len(data['users'])}")
    print(f"저장 위치: {output}")
    print("루트 계정과 SSO 사용자는 이번 수집 대상이 아닙니다.")


if __name__ == "__main__":
    main()