import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path


RULE_NAMES = {
    "IAM001": "전체 권한 허용",
    "IAM002": "서비스 전체 작업 허용",
    "IAM003": "콘솔 사용자 MFA 미설정",
    "IAM004": "오래된 활성 Access Key",
    "IAM005": "장기간 미사용 활성 키",
}

POLICY_RECOMMENDATION = (
    "업무에 필요한 작업과 리소스로 허용 범위를 제한하세요."
)


def safe(value):
    return escape(str(value), quote=True)


def render_html(report):
    if not isinstance(report, dict):
        raise ValueError("보고서는 JSON 객체여야 합니다.")

    findings = report.get("findings")
    unknowns = report.get("unknowns")
    summary = report.get("summary")

    if not isinstance(findings, list) or not isinstance(unknowns, list):
        raise ValueError("findings와 unknowns는 배열이어야 합니다.")

    if not isinstance(summary, dict):
        raise ValueError("summary는 JSON 객체여야 합니다.")

    if not all(isinstance(item, dict) for item in findings + unknowns):
        raise ValueError("분석 결과 항목은 JSON 객체여야 합니다.")

    limitations = report.get("limitations", [])
    sources = report.get("sources", {})

    if not isinstance(limitations, list) or not isinstance(sources, dict):
        raise ValueError("limitations 또는 sources 형식이 잘못되었습니다.")

    counts = Counter(
        str(item.get("rule_id", "알 수 없음"))
        for item in findings
    )

    rule_cards = []
    for rule_id in sorted(set(RULE_NAMES) | set(counts)):
        count = counts.get(rule_id, 0)
        state = "rule active" if count else "rule"
        rule_cards.append(
            f'<div class="{state}">'
            f'<div class="rule-code">{safe(rule_id)}</div>'
            f'<div class="rule-name">'
            f'{safe(RULE_NAMES.get(rule_id, "기타 규칙"))}</div>'
            f'<strong>{count}<small> 건</small></strong>'
            '</div>'
        )

    rows = []
    for finding in findings:
        rule_id = str(finding.get("rule_id", "알 수 없음"))
        user_name = finding.get("user_name")

        if user_name is not None:
            target = f"<strong>{safe(user_name)}</strong>"
        else:
            target = (
                "<strong>입력 정책</strong>"
                f'<div class="sub">구문 번호: '
                f'{safe(finding.get("statement", "-"))}</div>'
                f'<div class="sub">Sid: '
                f'{safe(finding.get("sid", "-"))}</div>'
            )

        if "key_id" in finding:
            target += (
                f'<div class="key">{safe(finding["key_id"])}</div>'
            )

        notes = []
        if "age_days" in finding:
            notes.append(f'생성 후 {finding["age_days"]}일 경과')
        if "unused_days" in finding:
            notes.append(f'미사용 기간 {finding["unused_days"]}일')
        if "threshold_days" in finding:
            notes.append(f'점검 기준 {finding["threshold_days"]}일 이상')
        if finding.get("has_condition"):
            notes.append("정책 조건이 있으므로 적용 조건 추가 확인 필요")
        if finding.get("usage_status") == "never_used":
            notes.append("사용 이력 없음: 생성 시각 기준으로 계산")

        note_html = "".join(
            f'<div class="sub">{safe(note)}</div>'
            for note in notes
        )

        recommendation = finding.get("recommendation")
        if not recommendation:
            recommendation = (
                POLICY_RECOMMENDATION
                if rule_id in ("IAM001", "IAM002")
                else "탐지 근거와 실제 설정을 확인하세요."
            )

        rows.append(
            "<tr>"
            f'<td><span class="badge">{safe(rule_id)}</span>'
            f'<div class="rule-label">'
            f'{safe(RULE_NAMES.get(rule_id, "기타 규칙"))}</div></td>'
            f"<td>{target}</td>"
            f'<td>{safe(finding.get("message", ""))}{note_html}</td>'
            f"<td>{safe(recommendation)}</td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            '<tr><td colspan="4" class="empty">'
            "현재 적용한 규칙에서 탐지된 항목이 없습니다. "
            "이 결과만으로 안전함을 판단할 수는 없습니다."
            "</td></tr>"
        )

    unknown_cards = []
    for item in unknowns:
        unknown_cards.append(
            '<div class="unknown-item">'
            f'<strong>{safe(item.get("user_name", "-"))}</strong>'
            f'<div class="key">{safe(item.get("key_id", "-"))}</div>'
            f'<p>{safe(item.get("message", ""))}</p>'
            "</div>"
        )

    if not unknown_cards:
        unknown_cards.append(
            '<p class="sub">보고된 판단 불가 항목이 없습니다.</p>'
        )

    source_html = "".join(
        f'<span class="source">{safe(label)}: '
        f'{safe(sources.get(field, "미기록"))}</span>'
        for field, label in (
            ("policy", "정책"),
            ("users", "사용자"),
            ("keys", "키"),
        )
    )
    limitation_html = "".join(
        f"<li>{safe(item)}</li>" for item in limitations
    )

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    collected_at = report.get("key_data_collected_at", "미기록")

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud IAM Analyzer · 보안 점검 보고서</title>
<style>
:root {{
    color-scheme: light;
    --text: #17243b;
    --muted: #59697e;
    --border: #dce4ee;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    background: #f3f6fb;
    color: var(--text);
    font-family: "Malgun Gothic", "Apple SD Gothic Neo", sans-serif;
    line-height: 1.65;
}}
main {{ max-width: 1240px; margin: auto; padding: 44px 24px; }}
header {{ margin-bottom: 26px; }}
.brand {{ color: #3158bb; font-weight: 800; letter-spacing: .08em; }}
h1 {{ font-size: 32px; margin: 8px 0; letter-spacing: -.04em; }}
h2 {{ font-size: 20px; margin: 0; }}
p {{ margin: 8px 0; }}
.subtitle, .sub {{ color: var(--muted); }}
.sub {{ font-size: 12px; margin-top: 6px; }}
.meta {{ font-size: 12px; color: var(--muted); margin-top: 16px; }}
.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}}
.card, .panel {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 16px;
}}
.card {{ padding: 22px; }}
.card-label {{ font-size: 14px; font-weight: 700; }}
.number {{ font-size: 38px; font-weight: 800; margin: 6px 0; }}
.card.warning {{ background: #fff7ed; border-color: #f2c994; }}
.card.warning .number {{ color: #a64409; }}
.card.info {{ background: #eff6ff; border-color: #b7d1f5; }}
.card.info .number {{ color: #245bb3; }}
.panel {{ padding: 24px; margin-bottom: 22px; }}
.section-note {{ color: var(--muted); font-size: 13px; margin: 6px 0 20px; }}
.rules {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
}}
.rule {{
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
    background: #f8fafc;
}}
.rule.active {{ background: #fffaf4; border-color: #efd1a9; }}
.rule-code {{ font-size: 12px; color: var(--muted); font-weight: 700; }}
.rule-name {{ font-size: 13px; min-height: 44px; margin: 6px 0; }}
.rule strong {{ font-size: 25px; }}
.rule small {{ font-size: 12px; font-weight: 400; }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; min-width: 850px; }}
th {{
    text-align: left;
    background: #f5f7fb;
    color: var(--muted);
    font-size: 12px;
    padding: 14px;
}}
td {{
    padding: 18px 14px;
    border-bottom: 1px solid #e8edf4;
    vertical-align: top;
    font-size: 13px;
    overflow-wrap: anywhere;
}}
th:nth-child(1) {{ width: 17%; }}
th:nth-child(2) {{ width: 24%; }}
th:nth-child(3) {{ width: 31%; }}
th:nth-child(4) {{ width: 28%; }}
tr:last-child td {{ border-bottom: none; }}
.badge {{
    display: inline-block;
    border-radius: 6px;
    background: #fff0d8;
    color: #8b4307;
    padding: 3px 8px;
    font-size: 12px;
    font-weight: 800;
}}
.rule-label {{ margin-top: 8px; font-size: 12px; }}
.key {{ font-family: monospace; font-size: 12px; color: var(--muted);
        overflow-wrap: anywhere; margin-top: 5px; }}
.unknown-item {{
    background: #eff6ff;
    border-left: 4px solid #477bd3;
    border-radius: 8px;
    padding: 16px;
    margin-top: 12px;
    font-size: 13px;
}}
.source {{
    display: inline-block;
    background: #f1f4f9;
    border-radius: 6px;
    padding: 5px 10px;
    margin: 4px 6px 4px 0;
    font-size: 12px;
    overflow-wrap: anywhere;
}}
ul {{ padding-left: 22px; color: var(--muted); font-size: 13px; }}
li {{ margin: 8px 0; }}
.empty {{ text-align: center; padding: 28px; color: var(--muted); }}
footer {{ text-align: center; color: var(--muted); font-size: 12px; }}
@media (max-width: 850px) {{
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
    .rules {{ grid-template-columns: repeat(2, 1fr); }}
}}
@media (max-width: 480px) {{
    main {{ padding: 24px 12px; }}
    .panel {{ padding: 16px; }}
    .card {{ padding: 16px; }}
    h1 {{ font-size: 26px; }}
}}
@media print {{
    body {{ background: white; }}
    main {{ max-width: none; padding: 0; }}
    .table-wrap {{ overflow: visible; }}
    table {{ min-width: 0; }}
    .card, .rule, tr {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<main>
<header>
    <div class="brand">CLOUD IAM ANALYZER</div>
    <h1>보안 점검 보고서</h1>
    <p class="subtitle">정책 권한 · 사용자 MFA · Access Key 점검 결과</p>
    <div class="meta">
        보고서 생성: {safe(generated_at)}<br>
        키 데이터 수집 시각: {safe(collected_at)}
    </div>
</header>

<section class="cards" aria-label="분석 요약">
    <div class="card warning">
        <div class="card-label">검토가 필요한 탐지</div>
        <div class="number">{len(findings)}</div>
        <div class="sub">규칙별 탐지 항목 수</div>
    </div>
    <div class="card info">
        <div class="card-label">판단 불가</div>
        <div class="number">{len(unknowns)}</div>
        <div class="sub">추가 정보 확인 필요</div>
    </div>
    <div class="card">
        <div class="card-label">분석한 사용자</div>
        <div class="number">{safe(summary.get("user_count", "-"))}</div>
        <div class="sub">입력된 IAM 사용자</div>
    </div>
    <div class="card">
        <div class="card-label">분석한 Access Key</div>
        <div class="number">{safe(summary.get("access_key_count", "-"))}</div>
        <div class="sub">입력된 활성·비활성 키</div>
    </div>
</section>

<section class="panel">
    <h2>규칙별 탐지 현황</h2>
    <p class="section-note">
        동일한 대상이 여러 규칙에 해당하면 각각 집계됩니다.
        색상은 검토 상태를 구분하며 위험도 등급을 뜻하지 않습니다.
    </p>
    <div class="rules">{"".join(rule_cards)}</div>
</section>

<section class="panel">
    <h2>탐지 상세</h2>
    <p class="section-note">대상과 탐지 근거를 확인한 뒤 개선 방안을 검토하세요.</p>
    <div class="table-wrap">
        <table>
            <thead><tr>
                <th scope="col">탐지 규칙</th>
                <th scope="col">대상</th>
                <th scope="col">탐지 근거</th>
                <th scope="col">개선 방안</th>
            </tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </div>
</section>

<section class="panel">
    <h2>판단 불가 항목</h2>
    <p class="section-note">
        정보 부족은 안전함이나 미사용을 의미하지 않습니다.
        같은 키가 다른 규칙에서는 탐지될 수 있습니다.
    </p>
    {"".join(unknown_cards)}
</section>

<section class="panel">
    <h2>분석 범위와 한계</h2>
    <p class="section-note">탐지 0건인 규칙도 전체 보안 상태의 안전을 보장하지 않습니다.</p>
    <div>{source_html}</div>
    <ul>{limitation_html}</ul>
</section>

<footer>Cloud IAM Analyzer · 입력 데이터를 기반으로 작성한 정적 분석 보고서</footer>
</main>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="통합 JSON 보고서를 HTML로 변환합니다."
    )
    parser.add_argument("input", type=Path, help="통합 JSON 보고서 경로")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("입력 파일과 출력 파일은 달라야 합니다.")

        with args.input.open(encoding="utf-8-sig") as file:
            report = json.load(file)

        html = render_html(report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(html, encoding="utf-8")

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] 보고서를 생성할 수 없습니다: {error}\n")

    print(f"HTML 보고서 저장: {args.output}")


if __name__ == "__main__":
    main()