import json
from pathlib import Path
from passrole_relationships import build_passrole_reviews

def build_relationships(data):
    details = data.get("authorization_details")
    if not isinstance(details, dict):
        raise ValueError("authorization_details가 필요합니다.")

    nodes = {}
    edges = set()
    warnings = []

    def add_node(node_id, kind, name, collected):
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("연결 대상의 ARN이 없거나 올바르지 않습니다.")

        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": kind,
                "name": name,
                "details_collected": collected,
            }
        elif collected:
            nodes[node_id]["details_collected"] = True
            nodes[node_id]["name"] = name

    def add_policy_reference(policy, source_id, relation):
        arn = policy.get("PolicyArn")
        name = policy.get("PolicyName") or arn
        add_node(arn, "managed_policy", name, False)
        edges.add((source_id, arn, relation))

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

    for policy in details["Policies"]:
        add_node(
            policy.get("Arn"),
            "managed_policy",
            policy.get("PolicyName", "(이름 없음)"),
            True,
        )

    groups_by_name = {}

    entity_types = (
        ("UserDetailList", "UserName", "user"),
        ("GroupDetailList", "GroupName", "group"),
        ("RoleDetailList", "RoleName", "role"),
    )

    for field, name_field, kind in entity_types:
        for entity in details[field]:
            arn = entity.get("Arn")
            name = entity.get(name_field)

            if not isinstance(name, str) or not name:
                raise ValueError(f"{name_field}이 없거나 올바르지 않습니다.")

            add_node(arn, kind, name, True)

            if kind == "group":
                if name in groups_by_name:
                    raise ValueError("중복된 그룹 이름이 있습니다.")
                groups_by_name[name] = arn

    for field, _, kind in entity_types:
        for entity in details[field]:
            source_id = entity["Arn"]
            attached = entity.get("AttachedManagedPolicies", [])

            if (
                not isinstance(attached, list)
                or not all(isinstance(item, dict) for item in attached)
            ):
                raise ValueError("AttachedManagedPolicies 형식이 잘못되었습니다.")

            for policy in attached:
                add_policy_reference(
                    policy,
                    source_id,
                    "attached_policy",
                )

            boundary = entity.get("PermissionsBoundary")
            if boundary is not None:
                if not isinstance(boundary, dict):
                    raise ValueError("PermissionsBoundary는 객체여야 합니다.")

                add_policy_reference(
                    {
                        "PolicyArn": boundary.get("PermissionsBoundaryArn")
                    },
                    source_id,
                    "permissions_boundary",
                )

            if kind == "user":
                group_names = entity.get("GroupList", [])
                if (
                    not isinstance(group_names, list)
                    or not all(isinstance(name, str) for name in group_names)
                ):
                    raise ValueError("GroupList는 문자열 배열이어야 합니다.")

                for group_name in group_names:
                    group_id = groups_by_name.get(group_name)

                    if group_id is None:
                        warnings.append({
                            "source": source_id,
                            "relation": "member_of",
                            "target_name": group_name,
                            "reason": "수집 데이터에서 그룹 상세를 찾지 못했습니다.",
                        })
                    else:
                        edges.add((source_id, group_id, "member_of"))

    node_list = sorted(nodes.values(), key=lambda node: node["id"])
    edge_list = [
        {
            "source": source,
            "target": target,
            "relation": relation,
        }
        for source, target, relation in sorted(edges)
    ]

    return {
        "schema_version": "1.0",
        "account_id": data.get("account_id"),
        "collected_at": data.get("collected_at"),
        "summary": {
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "warning_count": len(warnings),
        },
        "nodes": node_list,
        "edges": edge_list,
        "warnings": warnings,
        "limitations": [
            "수집된 IAM 설정의 연결 관계이며 실제 유효 권한을 뜻하지 않습니다.",
            "attached_policy는 관리형 정책 연결을 나타냅니다.",
            "member_of는 사용자의 그룹 소속을 나타냅니다.",
            "permissions_boundary는 권한 상한 설정이며 권한 부여가 아닙니다.",
            "상세가 수집되지 않은 정책은 참조 정보만 표시합니다.",
            "인라인 정책과 역할 신뢰 관계는 이번 연결 그래프에 포함하지 않습니다.",
            "이 그래프만으로 역할 수임이나 권한 상승 경로를 확정할 수 없습니다.",
        ],
    }


def main():
    root = Path(__file__).resolve().parent
    source = root / "data" / "private" / "policies.json"
    output = root / "reports" / "private" / "relationships.json"

    try:
        with source.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("수집 파일은 JSON 객체여야 합니다.")

        report = build_relationships(data)
        report["passrole_review"] = build_passrole_reviews(data, report)
        serialized = json.dumps(report, ensure_ascii=False, indent=2)

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(serialized + "\n", encoding="utf-8")
        temporary.replace(output)

    except (OSError, ValueError) as error:
        print(f"[ERROR] 관계 데이터 생성 실패: {error}")
        print("기존 결과 파일이 있다면 이전 실행 결과일 수 있습니다.")
        raise SystemExit(1)

    summary = report["summary"]
    print(f"노드 수: {summary['node_count']}")
    print(f"연결 수: {summary['edge_count']}")
    print(f"확인 필요 항목 수: {summary['warning_count']}")
    print(f"저장 위치: {output}")


if __name__ == "__main__":
    main()