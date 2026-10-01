import json
from collections import Counter
from html import escape
from pathlib import Path


TYPE_NAMES = {
    "user": "사용자",
    "role": "역할",
    "group": "그룹",
    "managed_policy": "관리형 정책",
}

RELATIONS = {
    "attached_policy": ("정책 연결", "#2563eb", ""),
    "member_of": ("그룹 소속", "#64748b", ""),
    "permissions_boundary": ("권한 경계", "#9333ea", "7 5"),
}


def safe(value):
    return escape(str(value), quote=True)


def _render_base_relationships(report):
    nodes = report["nodes"]
    edges = report["edges"]
    warnings = report["warnings"]

    columns = [[], [], []]
    for node in nodes:
        kind = node["type"]
        column = (
            2 if kind == "managed_policy"
            else 1 if kind == "group"
            else 0
        )
        columns[column].append(node)

    for column in columns:
        column.sort(key=lambda node: (node["type"], node["name"]))

    positions = {}
    node_by_id = {}

    for column_index, column in enumerate(columns):
        for row, node in enumerate(column):
            positions[node["id"]] = (
                40 + column_index * 370,
                80 + row * 110,
            )
            node_by_id[node["id"]] = node

    height = max(300, 110 * max(map(len, columns), default=0) + 100)

    lines = []
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        relation = edge["relation"]

        if source not in positions or target not in positions:
            raise ValueError("연결 대상 노드가 없습니다.")
        if relation not in RELATIONS:
            raise ValueError("지원하지 않는 연결 유형입니다.")

        label, color, dash = RELATIONS[relation]
        sx, sy = positions[source]
        tx, ty = positions[target]

        # 같은 대상에 정책 연결과 권한 경계가 있으면 선을 분리합니다.
        offset = 12 if relation == "permissions_boundary" else -6
        x1, y1 = sx + 270, sy + 35 + offset
        x2, y2 = tx, ty + 35 + offset
        mid = (x1 + x2) / 2

        lines.append(
            f'<path d="M {x1} {y1} C {mid} {y1}, '
            f'{mid} {y2}, {x2} {y2}" '
            f'fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-dasharray="{dash}" '
            f'marker-end="url(#{relation})">'
            f"<title>{safe(label)}</title></path>"
        )

    boxes = []
    for node in nodes:
        x, y = positions[node["id"]]
        kind = TYPE_NAMES.get(node["type"], node["type"])
        name = str(node["name"])
        short_name = name if len(name) <= 27 else name[:24] + "..."
        reference = (
            "" if node["details_collected"] else " · 상세 미수집"
        )

        boxes.append(
            "<g>"
            f"<title>{safe(name)}\n{safe(node['id'])}</title>"
            f'<rect x="{x}" y="{y}" width="270" height="76" '
            'rx="12" fill="white" stroke="#cbd5e1"/>'
            f'<text x="{x + 14}" y="{y + 25}" '
            f'class="node-type">{safe(kind + reference)}</text>'
            f'<text x="{x + 14}" y="{y + 51}" '
            f'class="node-name">{safe(short_name)}</text>'
            "</g>"
        )

    markers = "".join(
        f'<marker id="{relation}" markerWidth="8" markerHeight="8" '
        'refX="7" refY="4" orient="auto">'
        f'<path d="M 0 0 L 8 4 L 0 8 Z" fill="{color}"/>'
        "</marker>"
        for relation, (_, color, _) in RELATIONS.items()
    )

    rows = "".join(
        "<tr>"
        f"<td>{safe(node_by_id[edge['source']]['name'])}</td>"
        f"<td>{safe(RELATIONS[edge['relation']][0])}</td>"
        f"<td>{safe(node_by_id[edge['target']]['name'])}</td>"
        "</tr>"
        for edge in edges
    ) or '<tr><td colspan="3">기록된 연결이 없습니다.</td></tr>'

    warning_items = "".join(
        "<li>"
        f"{safe(item.get('target_name', '대상 미기록'))}: "
        f"{safe(item.get('reason', '사유 미기록'))}"
        "</li>"
        for item in warnings
    )

    limitations = "".join(
        f"<li>{safe(item)}</li>"
        for item in report.get("limitations", [])
    )
    counts = Counter(node["type"] for node in nodes)
    count_text = " · ".join(
        f"{label} {counts[kind]}개"
        for kind, label in TYPE_NAMES.items()
    )

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IAM 권한 연결 관계</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: #f3f6fb; color: #17243b;
    font-family: "Malgun Gothic", sans-serif; line-height: 1.7;
}}
main {{ max-width: 1240px; padding: 36px 24px; margin: auto; }}
h1 {{ margin: 6px 0; }}
h2 {{ font-size: 20px; margin-top: 0; }}
.brand {{ color: #3158bb; font-weight: 800; }}
.note {{ color: #59697e; font-size: 13px; }}
.panel {{
    background: white; padding: 24px; border-radius: 16px;
    border: 1px solid #dce4ee; margin-top: 22px;
}}
.graph {{ overflow-x: auto; background: #f8fafc; border-radius: 12px; }}
svg {{ display: block; width: 100%; min-width: 1100px; }}
.node-type {{ fill: #59697e; font-size: 12px; }}
.node-name {{ fill: #17243b; font-size: 14px; font-weight: 700; }}
.heading {{ fill: #59697e; font-size: 15px; font-weight: 700; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 20px; margin: 16px 0; }}
.legend span {{ font-size: 13px; }}
.blue {{ color: #2563eb; }}
.gray {{ color: #64748b; }}
.purple {{ color: #9333ea; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{
    text-align: left; padding: 13px;
    border-bottom: 1px solid #e8edf4;
    overflow-wrap: anywhere; font-size: 13px;
}}
th {{ background: #f5f7fb; }}
li {{ margin: 8px 0; }}
</style>
</head>
<body>
<main>
<div class="brand">CLOUD IAM ANALYZER</div>
<h1>IAM 권한 연결 관계</h1>
<p>{safe(count_text)}</p>
<p class="note">
    노드 {len(nodes)}개 · 연결 {len(edges)}개 · 확인 필요 {len(warnings)}건
</p>

<section class="panel">
    <h2>수집된 설정의 연결 그래프</h2>
    <p class="note">
        화살표는 소속 또는 정책 참조 방향입니다.
        역할 수임이나 권한 상승 경로를 뜻하지 않습니다.
        노드 위에 마우스를 올리면 전체 이름과 ARN을 확인할 수 있습니다.
    </p>
    <div class="legend">
        <span class="blue">파란 실선: 정책 연결</span>
        <span class="gray">회색 실선: 그룹 소속</span>
        <span class="purple">보라 점선: 권한 경계</span>
    </div>
    <div class="graph">
        <svg viewBox="0 0 1100 {height}" role="img"
             aria-label="IAM 사용자, 역할, 그룹, 정책 연결 그래프">
            <defs>{markers}</defs>
            <text x="40" y="40" class="heading">사용자 · 역할</text>
            <text x="410" y="40" class="heading">그룹</text>
            <text x="780" y="40" class="heading">관리형 정책</text>
            {"".join(lines)}
            {"".join(boxes)}
        </svg>
    </div>
</section>

<section class="panel">
    <h2>연결 상세</h2>
    <table>
        <thead><tr><th>출발 대상</th><th>관계</th><th>연결 대상</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</section>

<section class="panel">
    <h2>확인 필요 항목</h2>
    {"<ul>" + warning_items + "</ul>" if warnings else "<p>기록된 항목이 없습니다.</p>"}
</section>

<section class="panel">
    <h2>분석 범위와 한계</h2>
    <p class="note">수집 시각: {safe(report.get("collected_at", "미기록"))}</p>
    <ul>{limitations}</ul>
</section>
</main>
</body>
</html>
"""

def render_relationships(report):
    page = _render_base_relationships(report)
    review_data = report.get("passrole_review")

    if review_data is None:
        return page

    rows = []

    for review in review_data["reviews"]:
        resources = "<br>".join(
            safe(value) for value in review["wildcard_resources"]
        )
        condition = (
            safe(json.dumps(
                review["condition"],
                ensure_ascii=False,
                sort_keys=True,
            ))
            if review["has_condition"]
            else "해당 구문에 조건 없음"
        )

        for principal in review["principals"]:
            routes = []
            if principal["direct_attachment"]:
                routes.append("직접 정책 연결")
            routes.extend(
                f"그룹 경유: {group}"
                for group in principal["via_groups"]
            )

            rows.append(
                "<tr>"
                f"<td>{safe(review['policy_name'])}<br>"
                f"구문 #{safe(review['statement'])}</td>"
                f"<td>{safe(principal['name'])}<br>"
                f"{safe(principal['type'])}<br>"
                f"{safe(principal['arn'])}</td>"
                f"<td>{'<br>'.join(safe(route) for route in routes)}</td>"
                f"<td>{resources}</td>"
                f"<td>{condition}</td>"
                "</tr>"
            )

    table_rows = "".join(rows) or (
        '<tr><td colspan="5">'
        "분석한 범위에서 연결된 검토 대상이 없습니다."
        "</td></tr>"
    )

    skipped = "".join(
        f"<li>{safe(item['policy_arn'])}: {safe(item['reason'])}</li>"
        for item in review_data["skipped_policies"]
    )
    limitations = "".join(
        f"<li>{safe(item)}</li>"
        for item in review_data["limitations"]
    )

    section = f"""
    <section style="max-width:1200px;margin:24px auto;padding:24px;
                    background:white;border:1px solid #ddd;
                    border-radius:12px;overflow-wrap:anywhere">
      <h2>PassRole 검토 대상</h2>
      <p>연결된 정책의 탐지 구문:
         {safe(review_data["review_count"])}건 /
         분석 제외 정책:
         {len(review_data["skipped_policies"])}개</p>
      <p>아래 대상은 추가 검토가 필요합니다.
         실제 권한 부여 또는 권한 상승이 확인된 결과는 아닙니다.</p>
      <div style="overflow-x:auto">
        <table style="width:100%;min-width:850px">
          <thead><tr>
            <th>정책 / 구문</th><th>사용자·역할</th>
            <th>연결 경로</th><th>역할 리소스 범위</th><th>조건</th>
          </tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
      <h3>분석 제외 정책</h3>
      <ul>{skipped or "<li>없음</li>"}</ul>
      <h3>분석 범위와 한계</h3>
      <ul>{limitations}</ul>
    </section>
    """

    return page.replace("</body>", section + "</body>", 1)




def main():
    root = Path(__file__).resolve().parent
    source = root / "reports" / "private" / "relationships.json"
    output = root / "reports" / "private" / "relationships.html"

    try:
        with source.open(encoding="utf-8-sig") as file:
            report = json.load(file)

        html = render_relationships(report)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".html.tmp")
        temporary.write_text(html, encoding="utf-8")
        temporary.replace(output)

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"[ERROR] 관계 그래프 생성 실패: {error}")
        raise SystemExit(1)

    print(f"관계 그래프 저장: {output}")
    print("실제 계정 정보가 포함된 비공개 보고서입니다.")


if __name__ == "__main__":
    main()