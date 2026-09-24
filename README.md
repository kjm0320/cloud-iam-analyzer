# Cloud IAM Analyzer

AWS IAM 정책·사용자·Access Key 데이터를 분석하고,
탐지 근거와 개선 방안을 JSON 및 HTML 보고서로 제공하는
Python 보안 점검 도구입니다.

현재는 가상의 JSON 데이터를 이용한 오프라인 분석을 지원합니다.
최종 목표는 실제 AWS 계정에 읽기 전용으로 연결하여
수집부터 분석·보고서 생성까지 수행하는 것입니다.

## HTML 보고서

분석 결과를 다음 구성으로 제공합니다.

- 탐지 건수·판단 불가 건수·사용자 수·키 수 요약 카드
- 규칙별 탐지 건수
- 대상·탐지 근거·개선 방안 상세 표
- 판단 불가 항목
- 입력 파일과 분석 한계

보고서는 외부 서비스 연결 없이 브라우저에서 열 수 있습니다.
입력 데이터의 HTML 특수 문자를 이스케이프하여
사용자 이름이나 정책 내용이 HTML 코드로 해석되지 않도록 처리합니다.

색상은 검토 상태를 구분하며 위험도 등급을 의미하지 않습니다.

## 구현된 탐지 규칙

| 규칙 | 탐지 대상 |
|---|---|
| IAM001 | Allow 구문의 Action과 Resource에 각각 전체 범위 `*`가 포함된 경우 |
| IAM002 | Allow 구문에 `s3:*`처럼 서비스 전체 작업을 허용하는 Action이 포함된 경우 |
| IAM003 | 콘솔 로그인이 가능하지만 MFA가 설정되지 않은 IAM 사용자 |
| IAM004 | 생성 후 기준 기간 이상 지난 활성 Access Key |
| IAM005 | 기준 기간 이상 사용되지 않은 활성 Access Key |

IAM004와 IAM005의 기본 기준은 각각 90일입니다.
이는 프로젝트의 기본 점검 기준이며,
모든 환경에 일률적으로 적용해야 하는 보안 요구사항을 뜻하지 않습니다.

IAM002는 Resource가 제한되어 있어도 검토 대상으로 표시합니다.
동일한 대상이 여러 규칙에 해당하면 각각 집계합니다.

## 실행 환경

- Python 3.12 기준 GitHub Actions 테스트
- 현재 오프라인 기능은 Python 표준 라이브러리만 사용
- AWS 계정·인증 정보·외부 Python 패키지 설치 불필요

아래 명령어는 저장소 루트의 Windows CMD 기준입니다.
macOS와 Linux에서는 경로 구분자 `\`를 `/`로 바꿉니다.

## 빠른 실행

### 1. 통합 분석

```bat
python scan.py --policy samples\admin_policy.json --users samples\users.json --keys samples\unused_access_keys.json --output reports\combined_report.json
```

샘플 기준 예상 결과:

| 항목 | 건수 |
|---|---:|
| IAM001 | 1 |
| IAM003 | 1 |
| IAM004 | 4 |
| IAM005 | 2 |
| 전체 탐지 | 8 |
| 미사용 여부 판단 불가 | 1 |

이 명령어는 admin_policy.json을 사용하므로 IAM002 탐지는 없습니다.

사용 정보를 모르는 키도 생성 시각은 확인할 수 있습니다.
따라서 같은 키가 IAM004에서는 탐지되고
IAM005에서는 판단 불가로 분류될 수 있습니다.

### 2. HTML 보고서 생성

```bat
python html_report.py reports\combined_report.json --output reports\combined_report.html
```

### 3. 브라우저로 열기

```bat
start "" "reports\combined_report.html"
```

출력 폴더는 자동 생성합니다.
기존 출력 파일이 있으면 덮어씁니다.

## 개별 분석

### IAM 정책

```bat
python analyzer.py samples\admin_policy.json
python analyzer.py samples\limited_policy.json
python analyzer.py samples\service_wildcard_policy.json
```

예상 탐지 건수는 순서대로 1건, 0건, 1건입니다.
0건은 현재 규칙에 해당하지 않는다는 뜻이며 안전함을 보장하지 않습니다.

정책 분석 결과를 JSON으로 저장할 수도 있습니다.

```bat
python analyzer.py samples\service_wildcard_policy.json --output reports\service_wildcard_report.json
```

HTML 변환기는 scan.py로 생성한 통합 보고서를 입력으로 사용합니다.

### MFA

```bat
python account_analyzer.py samples\users.json
```

샘플 기준 IAM003 1건을 탐지합니다.

### 오래된 활성 Access Key

```bat
python access_key_analyzer.py samples\access_keys.json
```

기준 일수를 변경할 수 있습니다.

```bat
python access_key_analyzer.py samples\access_keys.json --max-age-days 120
```

### 장기간 미사용 활성 Access Key

```bat
python unused_key_analyzer.py samples\unused_access_keys.json
```

기준 일수를 변경할 수 있습니다.

```bat
python unused_key_analyzer.py samples\unused_access_keys.json --max-unused-days 120
```

현재 scan.py의 통합 분석은 각 규칙의 기본값인 90일을 사용합니다.

## 날짜와 사용 상태 처리

키의 경과 기간은 실행 시각이 아닌
입력 데이터의 collected_at을 기준으로 계산합니다.
이를 통해 같은 데이터의 분석 결과를 재현할 수 있습니다.

날짜에는 시간대가 필요하며 UTC로 변환하여 비교합니다.
생성 시각이 수집 시각보다 미래인 데이터는 거부합니다.

미사용 분석에는 다음 상태를 사용합니다.

| usage_status | 의미 | 처리 |
|---|---|---|
| used | 마지막 사용 시각 확인됨 | last_used_at부터 경과 기간 계산 |
| never_used | 사용한 적 없다고 확인됨 | created_at부터 경과 기간 계산 |
| unknown | 사용 정보를 확인할 수 없음 | 활성 키를 판단 불가로 분류 |

사용 정보가 없다는 이유만으로 미사용으로 단정하지 않습니다.
위 상태는 프로젝트의 분석용 형식이며 AWS 원본 응답 형식이 아닙니다.

## 입력 검증

- 정책의 Statement 구조 확인
- Effect가 Allow 또는 Deny인지 확인
- Action·Resource 누락, 빈 값, 잘못된 자료형 거부
- 현재 미지원인 NotAction·NotResource에 명시적 오류 표시
- 사용자 상태 필드의 불리언 자료형 확인
- 중복 사용자 이름 및 중복 키 ID 거부
- 날짜 형식·시간대·시간 순서 확인
- 사용 상태와 마지막 사용 시각의 일관성 확인

전체 AWS IAM 정책 문법을 검증하는 도구는 아닙니다.

## 테스트

```bat
python -m unittest discover -s tests -v
```

현재 자동 테스트는 57개입니다.

주요 검증 대상:

- 탐지 대상과 제외 대상
- 정확히 90일인 시점과 1초 부족한 시점
- 시간대 변환
- 누락·빈 값·잘못된 입력
- 판단 불가와 탐지 결과 분리
- JSON 보고서 저장
- 지정된 입력 파일 경로로의 덮어쓰기 방지
- 통합 분석 결과
- HTML 생성과 특수 문자 이스케이프

GitHub Actions에서 push와 pull request마다 테스트합니다.

## 주요 파일

| 파일 | 역할 |
|---|---|
| analyzer.py | IAM 정책 분석 |
| validation.py | 정책 입력 검증 |
| account_analyzer.py | 사용자 MFA 점검 |
| access_key_analyzer.py | 오래된 활성 키 점검 |
| unused_key_analyzer.py | 장기간 미사용 키 점검 |
| scan.py | 통합 분석 및 JSON 보고서 |
| html_report.py | 통합 JSON의 HTML 변환 |
| samples/ | 가상 입력 데이터 |
| reports/ | 가상 데이터의 예시 보고서 |
| tests/ | 자동 테스트 |
| .github/workflows/tests.yml | GitHub Actions 설정 |

## 분석 한계

- 현재 실제 AWS 계정에 연결하지 않습니다.
- 입력된 정책 한 개와 사용자·키 데이터만 분석합니다.
- 입력 데이터의 완전성이나 서로 간의 계정 연관성을 보장하지 않습니다.
- 실제 유효 권한과 Condition 충족 여부를 평가하지 않습니다.
- 다른 Statement나 정책의 Deny, 권한 경계, SCP 등을 종합 평가하지 않습니다.
- MFA 장치 설정 여부와 실제 로그인 시 MFA 강제 여부는 다릅니다.
- 루트 계정과 SSO 사용자는 현재 MFA 점검 대상에 포함되지 않습니다.
- 키의 경과 기간이나 미사용 기간만으로 유출 여부를 판단할 수 없습니다.
- 공개 접근 점검과 권한 상승 경로 분석은 아직 구현하지 않았습니다.
- 탐지 0건이 계정 전체의 안전함을 의미하지 않습니다.

## 데이터 관리

공개 저장소에는 가상의 샘플 데이터와 해당 분석 결과만 포함합니다.
실제 Access Key의 비밀 값은 분석 입력으로 필요하지 않습니다.

실제 계정 데이터와 보고서는 다음 경로에서 관리합니다.

- data/private/: 실제 계정 데이터
- reports/private/: 실제 데이터 기반 보고서

두 경로는 .gitignore에 등록되어 있습니다.
실제 데이터로 만든 HTML 보고서에도 계정 정보가 포함될 수 있으므로
동일하게 비공개 경로에 저장해야 합니다.

.gitignore는 이미 Git이 추적하는 파일에는 적용되지 않습니다.
커밋 전에 변경 내용을 확인합니다.

## 향후 개발 목표

- 비용이 발생하지 않는 범위를 확인한 뒤 AWS 읽기 전용 수집 기능 구현
- 실제 IAM 정책·사용자·역할·MFA·Access Key 정보와 분석기 연결
- 수집 실패·권한 부족·미확인 상태 구분
- 리소스 공개 접근 가능성 점검
- 권한 상승 후보 경로 분석 및 관계 시각화
- 실제 환경 검증 과정과 개선 전후 결과 문서화

최종 목표는 오프라인 재현성과 실제 AWS 적용 경험을 함께 갖춘
보안 분석 도구를 완성하는 것입니다.