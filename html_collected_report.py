import argparse
import copy
import json
from pathlib import Path

from html_report import RULE_NAMES, render_html, safe


RULE_NAMES["IAM006"] = "역할 신뢰 정책의 전체 Principal 허용"
RULE_NAMES["IAM008"] = "PassRole의 넓은 역할 허용 범위"

def render_skipped_items(items, name_field, owner_field=None):
    cards = []

    for item in items:
        owner_html = ""
        if owner_field and item.get(owner_field) is not None:
            owner_html = (
                f'<div class="sub">소유자: '
                f'{safe(item[owner_field])}</div>'
            )

        cards.append(
            '<div class="unknown-item">'
            f'<strong>{safe(item.get(name_field, "(이름 없음)"))}</strong>'
            f"{owner_html}"
            f'<p>{safe(item.get("reason", "사유 미기록"))}</p>'
            "</div>"
        )

    return "".join(cards) or '<p class="sub">분석 제외 항목이 없습니다.</p>'


def render_count_card(label, value):
    return (
        '<div class="rule">'
        f'<div class="rule-name">{safe(label)}</div>'
        f"<strong>{safe(value)}<small>개</small></strong>"
        "</div>"
    )


def render_collected_html(report):
    if not isinstance(report, dict):
        raise ValueError("보고서는 JSON 객체여야 합니다.")

    if report.get("report_type") != "aws_collected":
        raise ValueError(
            "scan_collected.py로 생성한 통합 보고서가 필요합니다."
        )

    summary = report.get("summary")
    findings = report.get("findings")
    skipped_policies = report.get("skipped_policies")
    skipped_roles = report.get("skipped_roles", [])
    collection_times = report.get("collection_times")

    if not isinstance(summary, dict):
        raise ValueError("summary는 JSON 객체여야 합니다.")

    for name, items in (
        ("findings", findings),
        ("skipped_policies", skipped_policies),
        ("skipped_roles", skipped_roles),
    ):
        if (
            not isinstance(items, list)
            or not all(isinstance(item, dict) for item in items)
        ):
            raise ValueError(f"{name}은 객체 배열이어야 합니다.")

    if not isinstance(collection_times, dict):
        raise ValueError("collection_times는 JSON 객체여야 합니다.")

    display_report = copy.deepcopy(report)

    owner_labels = {
        "user": "사용자",
        "group": "그룹",
        "role": "역할",
    }

    for finding in display_report["findings"]:
        context = []

        if finding.get("rule_id") == "IAM006":
            role_name = finding.get("role_name", "(이름 없음)")
            finding["user_name"] = f"역할: {role_name}"

            if finding.get("role_arn"):
                context.append(f"역할 ARN: {finding['role_arn']}")

            context.append(
                f"구문 번호: {finding.get('statement', '-')}"
            )
            context.append(f"Sid: {finding.get('sid', '-')}")

            if finding.get("has_condition"):
                context.append(
                    "검토 상태: 조건 검토 필요"
                )
                context.append(
                    "조건: "
                    + json.dumps(
                        finding.get("condition"),
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
            else:
                context.append("검토 상태: 조건 없음")

        elif finding.get("policy_type") in ("managed", "inline"):
            policy_name = finding.get("policy_name", "(이름 없음)")

            if finding["policy_type"] == "managed":
                finding["user_name"] = f"관리형 정책: {policy_name}"
                context.append(
                    f"기본 버전: {finding.get('version_id', '-')}"
                )
                if finding.get("policy_arn"):
                    context.append(
                        f"정책 ARN: {finding['policy_arn']}"
                    )
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
                    context.append(
                        f"소유자 ARN: {finding['owner_arn']}"
                    )

            context.append(
                f"구문 번호: {finding.get('statement', '-')}"
            )
            context.append(f"Sid: {finding.get('sid', '-')}")
        if finding.get("rule_id") == "IAM008":
            context.append(
                "허용 작업: "
                + ", ".join(finding.get("matching_actions", []))
            )
            context.append(
                "역할 범위: "
                + ", ".join(finding.get("wildcard_resources", []))
            )

            if finding.get("has_condition"):
                context.append(
                    "조건 검토 필요: "
                    + json.dumps(
                        finding.get("condition"),
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
            else:
                context.append("해당 구문에 조건 없음")

            context.append("실제 권한 상승 가능 여부는 별도 검증 필요")

        if context:
            finding["message"] = (
                str(finding.get("message", ""))
                + " / "
                + " / ".join(context)
            )

    html = render_html(display_report)

    policy_cards = "".join(
        render_count_card(label, summary.get(field, "미기록"))
        for label, field in (
            ("분석 대상 정책", "candidate_policy_count"),
            ("분석 완료 정책", "analyzed_policy_count"),
            ("분석 제외 정책", "skipped_policy_count"),
        )
    )

    trust_cards = "".join(
        render_count_card(label, summary.get(field, "미기록"))
        for label, field in (
            ("수집된 역할", "role_count"),
            ("신뢰 정책 분석 완료", "analyzed_role_count"),
            ("신뢰 정책 분석 제외", "skipped_role_count"),
            ("IAM006 검토 대상", "trust_finding_count"),
            ("조건 검토 필요", "trust_condition_review_count"),
        )
    )

    policy_skips_html = render_skipped_items(
        skipped_policies,
        "policy_name",
        "owner_name",
    )
    role_skips_html = render_skipped_items(
        skipped_roles,
        "role_name",
    )

    time_rows = "".join(
        "<tr>"
        f"<td>{safe(label)}</td>"
        f"<td>{safe(collection_times.get(field, '미기록'))}</td>"
        "</tr>"
        for field, label in (
            ("policies", "정책 및 역할 신뢰 정보"),
            ("users", "사용자 및 MFA"),
            ("keys", "Access Key"),
        )
    )

    extra_sections = f"""
<section class="panel">
    <h2>일반 권한 정책 분석 범위</h2>
    <p class="section-note">
        관리형 정책의 기본 버전과 인라인 정책을 분석합니다. IAM008은 활성화된 경우 함께 적용합니다.
        역할 신뢰 정책은 아래에서 별도로 집계합니다.
    </p>
    <div class="rules">{policy_cards}</div>
</section>

<section class="panel">
    <h2>역할 신뢰 정책 분석 현황</h2>
    <p class="section-note">
        조건 검토 필요 건수는 IAM006 검토 대상 건수에 포함됩니다.
        조건이 있는 구문을 무조건 외부 공개로 판정하지 않습니다.
    </p>
    <div class="rules">{trust_cards}</div>
    <p class="section-note">
        IAM006은 전체 Principal을 지정한 역할 수임 허용 구문을 점검합니다.
        실제 역할 수임 성공 여부와 특정 서비스·계정 신뢰의 적절성은
        판정하지 않습니다.
    </p>
</section>

<section class="panel">
    <h2>분석 제외 정책과 사유</h2>
    <p class="section-note">
        분석 제외는 안전 판정이 아닙니다.
        미지원 구문이나 입력 문제를 별도로 확인해야 합니다.
    </p>
    {policy_skips_html}
</section>

<section class="panel">
    <h2>신뢰 정책 분석 제외 역할과 사유</h2>
    <p class="section-note">
        문서 누락이나 미지원 형식으로 분석하지 못한 역할입니다.
    </p>
    {role_skips_html}
</section>

<section class="panel">
    <h2>데이터별 수집 시각</h2>
    <p class="section-note">
        각 수집기의 완료 시각이며,
        동일 순간의 계정 상태를 나타내지는 않습니다.
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