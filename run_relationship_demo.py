import json
from pathlib import Path

from build_relationships import build_relationships
from html_relationships import render_relationships


def make_demo_data():
    prefix = "arn:aws:iam::123456789012:"
    read_policy = prefix + "policy/demo-read"
    boundary_policy = prefix + "policy/demo-boundary"

    return {
        "source": "synthetic",
        "account_id": "123456789012",
        "collected_at": "2026-09-29T00:00:00+00:00",
        "authorization_details": {
            "Policies": [
                {
                    "Arn": read_policy,
                    "PolicyName": "demo-read",
                },
                {
                    "Arn": boundary_policy,
                    "PolicyName": "demo-boundary",
                },
            ],
            "UserDetailList": [{
                "Arn": prefix + "user/demo-user",
                "UserName": "demo-user",
                "GroupList": ["demo-developers"],
                "AttachedManagedPolicies": [],
                "PermissionsBoundary": {
                    "PermissionsBoundaryArn": boundary_policy,
                },
            }],
            "GroupDetailList": [{
                "Arn": prefix + "group/demo-developers",
                "GroupName": "demo-developers",
                "AttachedManagedPolicies": [{
                    "PolicyArn": read_policy,
                    "PolicyName": "demo-read",
                }],
            }],
            "RoleDetailList": [{
                "Arn": prefix + "role/demo-service-role",
                "RoleName": "demo-service-role",
                "AttachedManagedPolicies": [{
                    "PolicyArn": read_policy,
                    "PolicyName": "demo-read",
                }],
            }],
        },
    }


def main():
    root = Path(__file__).resolve().parent
    data = make_demo_data()
    report = build_relationships(data)

    expected = {
        "node_count": 5,
        "edge_count": 4,
        "warning_count": 0,
    }
    if report["summary"] != expected:
        raise ValueError("관계 그래프의 개수가 예상과 다릅니다.")

    prefix = "arn:aws:iam::123456789012:"
    actual_edges = {
        (edge["source"], edge["target"], edge["relation"])
        for edge in report["edges"]
    }
    expected_edges = {
        (
            prefix + "user/demo-user",
            prefix + "group/demo-developers",
            "member_of",
        ),
        (
            prefix + "user/demo-user",
            prefix + "policy/demo-boundary",
            "permissions_boundary",
        ),
        (
            prefix + "group/demo-developers",
            prefix + "policy/demo-read",
            "attached_policy",
        ),
        (
            prefix + "role/demo-service-role",
            prefix + "policy/demo-read",
            "attached_policy",
        ),
    }
    if actual_edges != expected_edges:
        raise ValueError("연결 관계가 예상과 다릅니다.")

    report["source"] = "synthetic"
    report["limitations"].insert(
        0,
        "공개용 가상 데이터입니다. 실제 AWS 계정과 연결하지 않습니다.",
    )
    html = render_relationships(report)

    files = {
        root / "samples" / "relationships_demo.json": data,
        root / "reports" / "demo" / "relationships.json": report,
    }

    for path, contents in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(contents, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    output = root / "reports" / "demo" / "relationships.html"
    output.write_text(html, encoding="utf-8")

    print("[성공] 가상 관계 그래프 검증 및 생성 완료")
    print("노드 5개 / 연결 4개 / 확인 필요 0건")
    print(f"HTML 저장: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"[ERROR] 관계 데모 생성 실패: {error}")
        raise SystemExit(1)