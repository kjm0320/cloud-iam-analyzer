import argparse
import copy
import json
from pathlib import Path

from html_report import render_html, safe


def render_collected_html(report):
    if not isinstance(report, dict):
        raise ValueError("보고서는 JSON 객체여야 합니다.")

    if report.get("report_type") != "aws_collected":
        raise ValueError(
            "scan_collected.py로 생성한 통합 보고서가 필요합니다."
        )

    summary = report.get("summary")
    findings = report.get("findings")
    skipped = report.get("skipped_policies")
    collection_times = report.get("collection_times")

    if not isinstance(summary, dict):
        raise ValueError("summary는 JSON 객체여야 합니다.")

    for name, items in (
        ("findings", findings),
        ("skipped_policies", skipped),
    ):
        if (
            not isinstance(items, list)
            or not all(isinstance(item, dict) for item in items)
        ):
            raise ValueError(f"{name}은 객체 배열이어야 합니다.")

    if not isinstance(collection_times, dict):
        raise ValueError("collection_times는 JSON 객체여야 합니다.")

    # 원본 보고서를 변경하지 않고 화면 표시용 복사본을 만듭니다.
    display_report = copy.deepcopy(report)

    owner_labels = {
        "user": "사용자",
        "group": "그룹",
        "role": "역할",
    }

    for finding in display_report["findings"]:
        policy_type = finding.get("policy_type")

        if policy_type not in ("managed", "inline"):
            continue

        policy_name = finding.get("policy_name", "(이름 없음)")
        context = []

        if policy_type == "managed":
            finding["user_name"] = f"관리형 정책: {policy_name}"
            context.append(
                f"기본 버전: {finding.get('version_id', '-')}"
            )
            if finding.get("policy_arn"):
                context.append(f"정책 ARN: {finding['policy_arn']}")
        else:
            finding["user_name"] = f"인라인 정책: {policy_name}"
            owner_type = owner_labels.get(
                finding.get("owner_type"), "대상"
            )
            context.append(
                f"소유 {owner_type}: "
                f"{finding.get('owner_name', '(이름 없음)')}"
            )
            if finding.get("owner_arn"):
                context.append(f"소유자 ARN: {finding['owner_arn']}")

        context.append(f"구문 번호: {finding.get('statement', '-')}")
        context.append(f"Sid: {finding.get('sid', '-')}")

        finding["message"] = (
            str(finding.get("message", ""))
            + " / "
            + " / ".join(context)
        )

    html = render_html(display_report)

    skipped_items = []
    for item in skipped:
        policy_name = item.get("policy_name", "(이름 없음)")
        owner_name = item.get("owner_name")
        owner_html = ""

        if owner_name is not None:
            owner_html = (
                f'<div class="sub">소유자: {safe(owner_name)}</div>'
            )

        skipped_items.append(
            '<div class="unknown-item">'
            f"<strong>{safe(policy_name)}</strong>"
            f"{owner_html}"
            f'<p>{safe(item.get("reason", "사유 미기록"))}</p>'
            "</div>"
        )

    if not skipped_items:
        skipped_items.append(
            '<p class="sub">문서별 분석에서 제외된 정책은 없습니다.</p>'
        )

    time_rows = "".join(
        "<tr>"
        f"<td>{safe(label)}</td>"
        f"<td>{safe(collection_times.get(field, '미기록'))}</td>"
        "</tr>"
        for field, label in (
            ("policies", "정책"),
            ("users", "사용자 및 MFA"),
            ("keys", "Access Key"),
        )
    )

    extra_sections = f"""
<section class="panel">
    <h2>실제 AWS 정책 분석 범위</h2>
    <p class="section-note">
        아래 개수는 일반 권한 정책 문서 기준입니다.
        역할 신뢰 정책과 리소스 정책은 포함하지 않습니다.
    </p>
    <div class="rules">
        <div class="rule">
            <div class="rule-name">분석 대상 정책</div>
            <strong>{safe(summary.get("candidate_policy_count", "-"))}
                <small>개</small>
            </strong>
        </div>
        <div class="rule">
            <div class="rule-name">분석 완료 정책</div>
            <strong>{safe(summary.get("analyzed_policy_count", "-"))}
                <small>개</small>
            </strong>
        </div>
        <div class="rule active">
            <div class="rule-name">분석 제외 정책</div>
            <strong>{len(skipped)}<small>개</small></strong>
        </div>
    </div>
    <p class="section-note">
        정책 구문의 탐지를 특정 사용자의 실제 유효 권한으로
        해석하면 안 됩니다. 정책 연결과 권한 경계의 영향은
        종합 평가하지 않습니다.
    </p>
</section>

<section class="panel">
    <h2>분석 제외 정책과 사유</h2>
    <p class="section-note">
        분석 제외는 안전 판정이 아닙니다.
        미지원 구문이나 입력 문제를 별도로 확인해야 합니다.
    </p>
    {"".join(skipped_items)}
</section>

<section class="panel">
    <h2>데이터별 수집 시각</h2>
    <p class="section-note">
        아래 시각은 각 수집기의 완료 시각입니다.
        세 파일이 동일 순간의 계정 상태를 나타내지는 않습니다.
    </p>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col">수집 데이터</th>
                    <th scope="col">수집 완료 시각</th>
                </tr>
            </thead>
            <tbody>{time_rows}</tbody>
        </table>
    </div>
</section>
"""

    if "<footer>" not in html:
        raise ValueError("기본 HTML 보고서의 삽입 위치를 찾지 못했습니다.")

    return html.replace(
        "<footer>",
        extra_sections + "\n<footer>",
        1,
    )


def main():
    project_root = Path(__file__).resolve().parent
    private_reports = project_root / "reports" / "private"

    parser = argparse.ArgumentParser(
        description="실제 AWS 통합 보고서를 HTML로 변환합니다."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=private_reports / "combined_report.json",
    )
    args = parser.parse_args()

    output = private_reports / "combined_report.html"
    temporary = output.with_suffix(".html.tmp")

    try:
        if args.input.resolve() == output.resolve():
            raise ValueError("입력 파일과 출력 파일은 달라야 합니다.")

        with args.input.open(encoding="utf-8-sig") as file:
            report = json.load(file)

        html = render_collected_html(report)

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(html, encoding="utf-8")
        temporary.replace(output)

    except (OSError, ValueError) as error:
        parser.exit(
            1,
            f"[ERROR] HTML 생성 실패: {error}\n"
            "기존 HTML 파일이 있다면 이전 실행 결과일 수 있습니다.\n",
        )

    print(f"실제 AWS HTML 보고서 저장: {output}")
    print("계정 정보가 포함된 비공개 보고서입니다.")


if __name__ == "__main__":
    main()