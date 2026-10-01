# Cloud IAM Analyzer

[![자동 테스트](https://github.com/kjm0320/cloud-iam-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/kjm0320/cloud-iam-analyzer/actions/workflows/tests.yml)

AWS IAM 정책·사용자·Access Key 정보를 수집하고,
보안 검토가 필요한 설정을 JSON 및 HTML 보고서로 제공하는 Python 프로젝트입니다.

AWS 계정 없이 실행하는 가상 데이터 데모와
실제 AWS 계정의 읽기 전용 수집을 지원합니다.

## 핵심 기능

- IAM 정책의 전체 권한 및 서비스 전체 작업 허용 탐지
- 콘솔 사용자 MFA 미설정 점검
- 오래된 활성 Access Key 및 장기간 미사용 키 점검
- 사용 정보가 부족한 키를 판단 불가로 구분
- 관리형 정책의 현재 기본 버전과 인라인 정책 분석
- 미지원 정책의 분석 제외 사유 기록
- 수집 파일 간 AWS 계정 ID·파티션 일치 확인
- JSON 및 HTML 보고서 생성
- 명령어 하나로 실제 AWS 수집부터 보고서 생성까지 실행
- 자동 테스트 95개와 GitHub Actions 데모 검증

## 탐지 규칙

| 규칙 | 탐지 대상 |
|---|---|
| IAM001 | Allow 구문의 Action과 Resource에 각각 `*`가 포함된 경우 |
| IAM002 | Allow 구문에 `s3:*`처럼 서비스 전체 작업을 허용하는 Action이 포함된 경우 |
| IAM003 | 콘솔 비밀번호가 있지만 MFA 장치가 설정되지 않은 IAM 사용자 |
| IAM004 | 생성 후 기준 기간 이상 지난 활성 Access Key |
| IAM005 | 기준 기간 이상 사용되지 않은 활성 Access Key |

IAM004와 IAM005의 기본 기준은 각각 90일입니다.
이는 프로젝트의 점검 기준이며 모든 환경에 적용되는 의무 기준은 아닙니다.

탐지 건수는 규칙별 항목 수입니다.
동일한 사용자나 키가 여러 규칙에 해당하면 각각 집계됩니다.

## 실행 환경

- Python 3.12
- 실제 AWS 수집: boto3 및 AWS 인증 프로필
- Windows CMD 기준 실행 예시
- macOS와 Linux에서는 경로 구분자를 `/`로 변경

## 설치

```bat
git clone https://github.com/kjm0320/cloud-iam-analyzer.git
cd cloud-iam-analyzer
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## AWS 계정 없이 데모 실행

```bat
python run_demo.py
```

실제 AWS에 접속하거나 설정을 변경하지 않습니다.
고정된 가상 데이터로 개선 전후를 비교합니다.

| 항목 | 개선 전 | 개선 후 |
|---|---:|---:|
| IAM001 | 1 | 0 |
| IAM002 | 1 | 0 |
| IAM003 | 1 | 0 |
| IAM004 | 2 | 0 |
| IAM005 | 1 | 0 |
| 전체 탐지 | 6 | 0 |
| 사용 정보 판단 불가 | 1 | 0 |

가상의 개선 내용:

- 전체 권한을 필요한 샘플 버킷의 객체 읽기 권한으로 제한
- 콘솔 사용자 MFA 설정
- 사용처 확인 후 불필요하다고 판단한 키 2개 비활성화

판단 불가 감소는 사용 이력을 새로 알아낸 결과가 아니라
해당 키를 비활성화하여 점검 대상에서 제외한 결과입니다.

### HTML 보고서 열기

```bat
start "" "reports\demo\before.html"
start "" "reports\demo\after.html"
```

### 생성 파일

- samples/demo/before/: 개선 전 가상 입력
- samples/demo/after/: 개선 후 가상 입력
- reports/demo/before.json
- reports/demo/after.json
- reports/demo/before.html
- reports/demo/after.html
- reports/demo/comparison.json

데모는 예상 탐지 결과와 다르면 오류로 종료합니다.

## 실제 AWS 계정 분석

### 인증과 권한

기본 프로필 이름은 `cloud-iam-analyzer`입니다.

수집에 사용하는 IAM 작업:

- iam:GetAccountAuthorizationDetails
- iam:ListUsers
- iam:GetLoginProfile
- iam:ListMFADevices
- iam:ListAccessKeys
- iam:GetAccessKeyLastUsed

추가로 STS GetCallerIdentity를 호출하여 수집 계정을 확인합니다.

이미 로컬에 설정한 AWS 프로필을 사용하며,
코드에 인증 정보를 넣지 않습니다.
루트 계정의 액세스 키는 사용하지 않습니다.

이 프로젝트의 수집기는 IAM·STS 조회만 수행합니다.
EC2 등 실행 자원을 생성하거나 IAM 설정과 키를 변경하지 않습니다.
AWS IAM Access Analyzer의 유료 분석 기능은 호출하지 않습니다.

### 한 번에 실행

```bat
python run_aws_scan.py --profile cloud-iam-analyzer
```

실행 순서:

1. IAM 사용자 및 MFA 수집
2. Access Key 메타데이터와 사용 정보 수집
3. IAM 정책 및 연결 정보 수집
4. 계정 정보 확인 및 통합 분석
5. HTML 보고서 생성

중간 단계가 실패하면 이후 단계를 실행하지 않습니다.
이 경우 일부 수집 파일은 갱신되었을 수 있고,
기존 보고서는 이전 실행 결과일 수 있습니다.
문제를 해결한 뒤 전체 명령어를 다시 실행합니다.

### 실제 보고서 열기

```bat
start "" "reports\private\combined_report.html"
```

실제 계정 데이터와 보고서는 다음 위치에 저장합니다.

- data/private/users.json
- data/private/access_keys.json
- data/private/policies.json
- reports/private/combined_report.json
- reports/private/combined_report.html

## 개별 실행

### 계정 확인

```bat
python aws_identity.py --profile cloud-iam-analyzer
```

### 데이터 수집

```bat
python collect_users.py --profile cloud-iam-analyzer
python collect_access_keys.py --profile cloud-iam-analyzer
python collect_policies.py --profile cloud-iam-analyzer
```

### 수집 파일 분석

```bat
python account_analyzer.py data\private\users.json
python access_key_analyzer.py data\private\access_keys.json
python unused_key_analyzer.py data\private\access_keys.json
python analyze_collected_policies.py
```

### 통합 보고서 생성

```bat
python scan_collected.py
python html_collected_report.py
```

### 단일 정책 분석

```bat
python analyzer.py samples\admin_policy.json
python analyzer.py samples\limited_policy.json
python analyzer.py samples\service_wildcard_policy.json
```

### 개별 키 분석 기준 변경

```bat
python access_key_analyzer.py data\private\access_keys.json --max-age-days 120
python unused_key_analyzer.py data\private\access_keys.json --max-unused-days 120
```

현재 통합 분석은 기본값인 90일을 사용합니다.

## 분석 결과 해석

### 사용 시각이 없는 키

실제 AWS 수집에서는 마지막 사용 시각이 없으면
`unknown`으로 저장합니다.
이를 사용한 적 없는 키로 단정하지 않습니다.

활성 키의 사용 정보가 unknown이면 판단 불가로 기록합니다.
비활성 키는 IAM004·IAM005 및 미사용 판단 불가 집계에서 제외합니다.

### 정책 분석 범위

관리형 정책은 현재 기본 버전만 분석합니다.
사용자·그룹·역할의 인라인 정책은 각각 분석합니다.

현재 NotAction·NotResource는 지원하지 않으며,
해당 정책은 사유와 함께 분석 제외로 기록합니다.
역할 신뢰 정책은 일반 권한 정책 분석에 포함하지 않습니다.

### 계정 일치 확인

수집 파일에 기록된 계정 ID·파티션과 호출자 ARN을 확인합니다.
파일 간 계정이나 파티션이 다르면 통합 분석을 중단합니다.

이 검증은 파일 혼용을 줄이기 위한 장치입니다.
로컬 파일의 위변조 여부를 증명하지 않으며,
서로 다른 시점에 수집된 데이터의 일관성까지 보장하지 않습니다.

## HTML 보고서

- 탐지·판단 불가·사용자·키 개수 요약
- 규칙별 탐지 건수
- 대상·탐지 근거·개선 방안
- 실제 정책 이름·기본 버전·인라인 정책 소유자
- 분석 완료·제외 정책 수와 제외 사유
- 데이터별 수집 시각과 분석 한계

외부 웹 자원 없이 브라우저에서 열 수 있습니다.
동적 텍스트는 HTML 특수 문자를 이스케이프합니다.

색상은 검토 상태를 구분하며 위험도 등급을 의미하지 않습니다.

## 테스트 및 CI

```bat
python -m unittest discover -s tests -v
```

현재 테스트는 95개입니다.

주요 검증 내용:

- 탐지 대상과 제외 대상
- 기간 경계와 시간대 처리
- 입력 검증과 판단 불가 처리
- AWS 응답의 페이지 처리 및 오류 전파
- 정책 기본 버전 선택과 분석 제외 처리
- 계정 및 파티션 불일치 거부
- JSON·HTML 생성과 HTML 이스케이프
- 입력 파일 덮어쓰기 방지
- 실행 단계 실패 시 후속 단계 중단

GitHub Actions는 자동 테스트와 가상 데이터 데모를 실행합니다.
CI에서는 실제 AWS에 접속하지 않으며 AWS 인증 키가 필요하지 않습니다.

## 데이터 관리

공개 저장소에는 코드·가상 데이터·가상 데이터 보고서만 포함합니다.

다음 경로는 .gitignore에 등록되어 있습니다.

- data/private/
- reports/private/
- .aws/
- .env 및 관련 환경 파일

실제 보고서에는 계정 ID, 사용자 이름, 정책 ARN, 키 ID 등이
포함될 수 있으므로 공개하지 않습니다.
비밀 액세스 키 값은 수집하거나 보고서에 저장하지 않습니다.

.gitignore는 이미 추적 중인 파일에는 적용되지 않습니다.
커밋 전에 변경 파일을 확인합니다.

## 분석 한계

- 탐지 0건이 계정 전체의 안전함을 의미하지 않습니다.
- 실제 유효 권한을 계산하는 IAM 정책 평가 엔진이 아닙니다.
- 명시적 거부, Condition, SCP, 권한 경계를 종합 평가하지 않습니다.
- 관리형 정책의 탐지가 특정 사용자에게 해당 권한이 있음을 뜻하지 않습니다.
- MFA 장치 설정 여부와 MFA 사용 강제 여부는 다릅니다.
- 루트 계정과 SSO 사용자는 사용자·키 점검 대상에 포함되지 않습니다.
- 키의 경과 기간과 사용 이력만으로 유출 여부를 판단하지 않습니다.
- 여러 API를 순차 호출하므로 동일 순간의 스냅샷은 아닙니다.
- 현재 전체 AWS 정책 문법을 검증하지 않습니다.

## 향후 개발

- 리소스 공개 접근 가능성 점검
- 역할 신뢰 관계 및 권한 상승 후보 경로 분석
- 권한 관계 시각화
- 탐지 규칙의 적용 범위와 오탐 처리 개선
- 실제 검증 경험을 민감정보 없이 문서화

## 프로젝트 목표

샘플로 누구나 재현할 수 있고,
실제 AWS 계정에도 읽기 전용으로 적용할 수 있는
보안 분석 도구를 만드는 것입니다.

## IAM 관계 그래프

사용자·그룹·역할·관리형 정책의 연결 관계를 HTML로 시각화합니다.

- 그룹 소속
- 관리형 정책 연결
- 권한 경계 연결: 보라색 점선으로 구분

권한 경계는 권한을 부여하는 정책이 아니라 허용 가능한 권한의 상한입니다. 그래프는 수집한 설정의 연결 관계를 보여주며, 실제 유효 권한이나 권한 상승 가능성을 확정하지 않습니다.

### AWS 계정 없이 데모 실행

합성 데이터로 그래프를 생성하고 노드 5개와 연결 4개를 검증합니다. AWS API를 호출하지 않습니다.

```cmd
python run_relationship_demo.py
start "" "reports\demo\relationships.html"
```

GitHub Actions에서도 이 데모를 실행해 관계 생성 결과를 검증합니다.

### 수집한 AWS 데이터로 실행

기존에 수집한 `data/private/policies.json`이 필요합니다.

```cmd
python build_relationships.py
python html_relationships.py
start "" "reports\private\relationships.html"
```

전체 수집·분석 명령에도 관계 그래프 생성이 포함되어 있습니다.

```cmd
python run_aws_scan.py --profile cloud-iam-analyzer
```

실제 AWS 수집 데이터와 보고서는 `data/private/`, `reports/private/`에 저장하며 GitHub 공개 대상에서 제외합니다.


### PassRole 검토 대상 연결 분석

넓은 역할 범위를 허용하는 `iam:PassRole` 구문을 탐지하고, 해당 관리형 정책에 연결된 사용자·역할을 HTML 관계 그래프 아래 표에 표시합니다.

- 사용자·역할에 직접 연결된 관리형 정책 추적
- 그룹에 연결된 관리형 정책과 소속 사용자 연결
- 권한 경계 연결은 권한 부여 경로에서 제외
- 정책 구문, 역할 리소스 범위, 조건 및 연결 경로 표시
- 분석하지 못한 정책과 제외 사유 표시

#### AWS 없이 데모 실행

```cmd
python run_passrole_demo.py
start "" "reports\demo\passrole_relationships.html"
```

합성 데이터에서 탐지 구문 1개와 검토 대상 2개를 검증합니다.

| 검토 대상 | 정책 연결 경로 |
| --- | --- |
| demo-user | 그룹 경유 |
| demo-service-role | 직접 연결 |

AWS API를 호출하지 않으며, GitHub Actions에서도 데모 결과를 검증합니다.

#### 분석 한계

이 연결 분석은 관리형 정책을 대상으로 하며 인라인 정책은 포함하지 않습니다. 조건, 명시적 거부, 권한 경계, SCP를 종합 평가하지 않습니다.

전달 대상 역할의 권한·신뢰 정책과 서비스 작업 권한을 함께 검증하지 않으므로, 결과는 추가 검토 후보입니다. 실제 PassRole 허용 여부나 권한 상승 가능성을 확정하지 않습니다.

