from analyze_collected_policies import decode_document
from passrole_analyzer import analyze_passrole


def build_passrole_reviews(data, graph):
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = graph["edges"]
    reviews = []
    skipped = []

    for policy in data["authorization_details"]["Policies"]:
        policy_arn = policy["Arn"]

        attached = {
            edge["source"]
            for edge in edges
            if edge["relation"] == "attached_policy"
            and edge["target"] == policy_arn
        }

        principals = {
            node_id
            for node_id in attached
            if nodes[node_id]["type"] in ("user", "role")
        }

        principals.update(
            edge["source"]
            for edge in edges
            if edge["relation"] == "member_of"
            and edge["target"] in attached
            and nodes[edge["source"]]["type"] == "user"
        )

        if not principals:
            continue

        try:
            default_id = policy.get("DefaultVersionId")
            versions = [
                version
                for version in policy.get("PolicyVersionList", [])
                if default_id
                and version.get("VersionId") == default_id
                and version.get("IsDefaultVersion") is True
            ]

            if len(versions) != 1:
                raise ValueError("기본 정책 버전을 하나로 확인할 수 없습니다.")

            document = decode_document(versions[0]["Document"])
            findings = analyze_passrole(document)

        except (KeyError, TypeError, ValueError) as error:
            skipped.append({
                "policy_arn": policy_arn,
                "reason": str(error),
            })
            continue

        for finding in findings:
            reviews.append({
                **finding,
                "policy_arn": policy_arn,
                "policy_name": policy.get("PolicyName", policy_arn),
                "review_status": "requires_review",
                "principals": [
                    {
                        "arn": node_id,
                        "name": nodes[node_id]["name"],
                        "type": nodes[node_id]["type"],
                        "via_groups": sorted({
                            edge["target"]
                            for edge in edges
                            if edge["relation"] == "member_of"
                            and edge["source"] == node_id
                            and edge["target"] in attached
                        }),
                        "direct_attachment": node_id in attached,
                    }
                    for node_id in sorted(principals)
                ],
            })

    return {
        "review_count": len(reviews),
        "reviews": reviews,
        "skipped_policies": skipped,
        "limitations": [
            "관리형 정책의 직접 연결과 그룹 소속만 추적합니다.",
            "인라인 정책은 이번 연결 분석에 포함하지 않습니다.",
            "권한 경계 연결을 권한 부여로 취급하지 않습니다.",
            "조건, 명시적 거부, 권한 경계, SCP를 종합 평가하지 않습니다.",
            "전달 대상 역할과 서비스 작업 권한은 검증하지 않습니다.",
            "실제 PassRole 허용 여부나 권한 상승 가능성을 확정하지 않습니다.",
        ],
    }