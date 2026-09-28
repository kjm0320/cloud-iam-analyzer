import argparse
import json
from html import escape
from pathlib import Path

from s3_analyzer import analyze_s3


def safe(value):
    return escape(str(value), quote=True)


def render_s3_html(report, source_name, data_source):
    summary = report["summary"]

    groups = (
        ("findings", "검토 필요", "warning"),
        ("unknowns", "판단 불가", "unknown"),
        ("restricted", "제한 설정 확인", "restricted"),
        ("not_flagged", "규칙 해당 없음", "neutral"),
    )

    cards = "".join(
        f'<div class="card {style}">'
        f'<span>{label}</span>'
        f'<strong>{len(report[key])}<small> 건</small></strong>'
        "</div>"
        for key, label, style in groups
    )

    rows = []

    policy_labels = {
        "public": "공개 정책",
        "nonpublic": "비공개 정책",
        "absent": "정책 없음",
        "unknown": "확인 불가",
    }

    for key, label, style in groups:
        for item in report[key]:
            restriction = item["effective_restrict_public_buckets"]
            if restriction is True:
                restriction_label = "켜짐"
            elif restriction is False:
                restriction_label = "꺼짐"
            else:
                restriction_label = "확인 불가"

            recommendation = item.get("recommendation", "")

            if key == "unknowns":
                recommendation = (
                    "정책 공개 상태 또는 차단 설정의 조회 결과를 확인하세요."
                )
            elif key == "restricted":
                recommendation = (
                    "현재 제한 설정을 유지하고 공개 정책의 필요성을 검토하세요."
                )
            elif key == "not_flagged":
                recommendation = (
                    "이번 규칙의 대상은 아닙니다. 다른 접근 경로는 별도 점검하세요."
                )

            rows.append(
                "<tr>"
                f"<td><strong>{safe(item['bucket_name'])}</strong></td>"
                f'<td><span class="badge {style}">{label}</span></td>'
                f"<td>{safe(policy_labels[item['policy_status']])}</td>"
                f"<td>{restriction_label}</td>"
                f"<td>{safe(item['message'])}"
                f'<p class="recommendation">{safe(recommendation)}</p></td>'
                "</tr>"
            )

    if not rows:
        rows.append(
            '<tr><td colspan="5" class="empty">'
            "입력된 버킷이 없습니다. 계정에 버킷이 없음을 검증한 결과는 아닙니다."
            "</td></tr>"
        )

    limitations = "".join(
        f"<li>{safe(item)}</li>"
        for item in report["limitations"]
    )

    data_label = (
        "공개용 가상 데이터"
        if data_source == "synthetic"
        else "입력 파일 기반 분석 · 데이터 출처 별도 확인 필요"
    )

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>S3 공개 접근 점검 보고서</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: #f3f6fb; color: #17243b;
    font-family: "Malgun Gothic", "Apple SD Gothic Neo", sans-serif;
    line-height: 1.7;
}}
main {{ max-width: 1240px; margin: auto; padding: 40px 24px; }}
.brand {{ color: #3158bb; font-weight: 800; letter-spacing: .08em; }}
h1 {{ font-size: 30px; margin: 8px 0; }}
h2 {{ font-size: 20px; margin: 0 0 10px; }}
.subtitle, .note {{ color: #59697e; }}
.note {{ font-size: 13px; }}
.source {{
    display: inline-block; padding: 6px 12px; margin: 10px 0 24px;
    border-radius: 8px; background: #e8eef9; font-size: 13px;
}}
.cards {{
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 16px; margin-bottom: 24px;
}}
.card {{
    padding: 22px; border: 1px solid #dce4ee;
    border-radius: 14px; background: white;
}}
.card span {{ font-size: 14px; font-weight: 700; }}
.card strong {{ display: block; font-size: 36px; margin-top: 6px; }}
.card small {{ font-size: 14px; font-weight: 400; }}
.warning {{ background: #fff4e5; color: #8f4205; }}
.unknown {{ background: #edf4ff; color: #245bb3; }}
.restricted {{ background: #eaf6f3; color: #216456; }}
.neutral {{ background: #eef1f6; color: #4b5c72; }}
.panel {{
    background: white; border: 1px solid #dce4ee;
    border-radius: 16px; padding: 24px; margin-bottom: 24px;
}}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; min-width: 900px; }}
th {{
    text-align: left; padding: 14px; background: #f5f7fb;
    color: #59697e; font-size: 12px;
}}
td {{
    padding: 18px 14px; border-bottom: 1px solid #e8edf4;
    vertical-align: top; font-size: 13px; overflow-wrap: anywhere;
}}
th:nth-child(1) {{ width: 22%; }}
th:nth-child(2) {{ width: 13%; }}
th:nth-child(3) {{ width: 12%; }}
th:nth-child(4) {{ width: 13%; }}
th:nth-child(5) {{ width: 40%; }}
.badge {{
    display: inline-block; padding: 4px 8px;
    border-radius: 6px; font-size: 12px; font-weight: 700;
}}
.recommendation {{ color: #59697e; margin: 8px 0 0; }}
li {{ margin: 8px 0; }}
.empty {{ text-align: center; padding: 28px; }}
footer {{ text-align: center; color: #59697e; font-size: 12px; }}
@media (max-width: 760px) {{
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
    main {{ padding: 24px 12px; }}
    .panel {{ padding: 16px; }}
}}
@media print {{
    body {{ background: white; }}
    main {{ padding: 0; }}
    .table-wrap {{ overflow: visible; }}
    table {{ min-width: 0; }}
    tr, .card {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<main>
<header>
    <div class="brand">CLOUD IAM ANALYZER</div>
    <h1>S3 공개 접근 점검</h1>
    <p class="subtitle">
        IAM007 · 버킷 정책과 계정·버킷의 공개 접근 제한 설정
    </p>
    <div class="source">{safe(data_label)}</div>
</header>

<section class="cards" aria-label="점검 결과 요약">
    {cards}
</section>

<section class="panel">
    <h2>버킷별 점검 결과</h2>
    <p class="note">
        입력 버킷 {safe(summary["bucket_count"])}개 ·
        색상은 결과 분류이며 위험도 등급이 아닙니다.
    </p>
    <div class="table-wrap">
        <table>
            <thead><tr>
                <th scope="col">버킷</th>
                <th scope="col">점검 결과</th>
                <th scope="col">정책 상태</th>
                <th scope="col">접근 제한 설정</th>
                <th scope="col">근거 및 후속 검토</th>
            </tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </div>
</section>

<section class="panel">
    <h2>설정 해석</h2>
    <p>
        접근 제한 설정은 계정과 버킷의
        <strong>RestrictPublicBuckets</strong>를 함께 확인한 값입니다.
        둘 중 하나가 켜져 있으면 제한 설정을 확인한 것으로 분류합니다.
    </p>
    <p>
        <strong>BlockPublicPolicy</strong>는 새 공개 정책 등록을 막는 설정입니다.
        이 값만으로 기존 공개 정책의 접근이 제한된다고 판단하지 않습니다.
    </p>
    <p class="note">
        제한 설정 확인은 버킷 전체가 안전하다는 판정이 아닙니다.
    </p>
</section>

<section class="panel">
    <h2>입력 및 분석 한계</h2>
    <p class="note">입력 파일: {safe(source_name)}</p>
    <ul>{limitations}</ul>
</section>

<footer>실제 객체 접근이나 AWS 설정 변경을 수행하지 않는 정적 분석 보고서</footer>
</main>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="S3 점검 데이터를 분석하여 HTML 보고서를 생성합니다."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("입력 파일과 출력 파일은 달라야 합니다.")

        with args.input.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        report = analyze_s3(data)
        html = render_s3_html(
            report,
            args.input.name,
            data.get("source", "unknown"),
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(html, encoding="utf-8")
        temporary.replace(args.output)

    except (OSError, ValueError) as error:
        parser.exit(1, f"[ERROR] S3 HTML 생성 실패: {error}\n")

    print(f"S3 HTML 보고서 저장: {args.output}")


if __name__ == "__main__":
    main()