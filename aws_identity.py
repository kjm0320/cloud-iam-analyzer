import argparse
import re

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def get_account_identity(sts):
    response = sts.get_caller_identity()

    account_id = response.get("Account")
    caller_arn = response.get("Arn")

    if (
        not isinstance(account_id, str)
        or re.fullmatch(r"[0-9]{12}", account_id) is None
    ):
        raise ValueError("AWS 응답의 계정 ID가 올바르지 않습니다.")

    if not isinstance(caller_arn, str):
        raise ValueError("AWS 응답에 호출자 ARN이 없습니다.")

    parts = caller_arn.split(":", 5)

    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not parts[1]
        or parts[2] not in ("iam", "sts")
        or parts[4] != account_id
        or not parts[5]
    ):
        raise ValueError("호출자 ARN과 계정 ID를 확인할 수 없습니다.")

    return {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "partition": parts[1],
    }


def main():
    parser = argparse.ArgumentParser(
        description="AWS 프로필의 계정 정보를 확인합니다."
    )
    parser.add_argument(
        "--profile",
        default="cloud-iam-analyzer",
        help="확인할 AWS CLI 프로필 이름",
    )
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile)
        sts = session.client(
            "sts",
            region_name=session.region_name or "ap-northeast-2",
            config=Config(
                connect_timeout=10,
                read_timeout=30,
                retries={
                    "mode": "standard",
                    "total_max_attempts": 3,
                },
            ),
        )

        identity = get_account_identity(sts)

    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        parser.exit(
            1,
            f"[ERROR] 계정 확인 실패: {error.operation_name} / {code}\n",
        )
    except (BotoCoreError, ValueError) as error:
        parser.exit(1, f"[ERROR] 계정 확인 실패: {error}\n")

    masked_id = "*" * 8 + identity["account_id"][-4:]

    print("[성공] AWS 인증 계정을 확인했습니다.")
    print(f"계정 ID: {masked_id}")
    print(f"AWS 파티션: {identity['partition']}")
    print("호출자 ARN과 계정 ID가 일치합니다.")


if __name__ == "__main__":
    main()