import json
from pathlib import Path

from build_relationships import build_relationships
from html_relationships import render_relationships
from passrole_relationships import build_passrole_reviews
from run_relationship_demo import make_demo_data


def main():
    data = make_demo_data()
    details = data["authorization_details"]

    policy = next(
        item
        for item in details["Policies"]
        if item["Arn"].endswith("policy/demo-read")
    )
    policy["DefaultVersionId"] = "v1"
    policy["PolicyVersionList"] = [{
        "VersionId": "v1",
        "IsDefaultVersion": True,
        "Document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DemoBroadPassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": "ec2.amazonaws.com",
                    },
                },
            }],
        },
    }]

    report = build_relationships(data)
    report["source"] = "synthetic"
    report["limitations"].insert(
        0,
        "공개용 가상 데이터입니다. AWS API를 호출하지 않습니다.",
    )
    review = build_passrole_reviews(data, report)
    report["passrole_review"] = review

    if review["review_count"] != 1 or review["skipped_policies"]:
        raise ValueError("PassRole 탐지 구문 수 또는 분석 제외 결과가 다릅니다.")

    finding = review["reviews"][0]
    principals = {
        item["name"]: item
        for item in finding["principals"]
    }

    if set(principals) != {"demo-user", "demo-service-role"}:
        raise ValueError("검토 대상 사용자·역할이 예상과 다릅니다.")

    if (
        principals["demo-user"]["direct_attachment"]
        or not principals["demo-user"]["via_groups"]
        or not principals["demo-service-role"]["direct_attachment"]
        or not finding["has_condition"]
    ):
        raise ValueError("연결 경로 또는 조건 정보가 예상과 다릅니다.")

    html = render_relationships(report)
    output = Path(__file__).resolve().parent / "reports" / "demo"
    output.mkdir(parents=True, exist_ok=True)

    (output / "passrole_relationships.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "passrole_relationships.html").write_text(
        html,
        encoding="utf-8",
    )

    print("[성공] PassRole 연결 데모 검증 완료")
    print("탐지 구문: 1개 / 연결된 검토 대상: 2개")
    print("demo-user: 그룹 경유 / demo-service-role: 직접 연결")
    print(f"HTML 저장: {output / 'passrole_relationships.html'}")


if __name__ == "__main__":
    main()