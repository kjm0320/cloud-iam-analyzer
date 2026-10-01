# Cloud IAM Analyzer

[![자동 테스트](https://github.com/kjm0320/cloud-iam-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/kjm0320/cloud-iam-analyzer/actions/workflows/tests.yml)

AWS IAM 정책·사용자·Access Key·역할 신뢰 정책을 분석하고, 보안 검토가 필요한 설정을 JSON 및 HTML 보고서로 제공하는 Python 프로젝트입니다.

AWS 계정 없이 실행할 수 있는 가상 데이터 데모와 실제 AWS 계정의 읽기 전용 수집을 지원합니다. 수집한 IAM 연결 관계를 시각화하고, 넓은 PassRole 허용 구문이 발견된 관리형 정책에 연결된 사용자·역할을 추적합니다.

> 이 프로젝트는 보안 설정 검토를 돕는 정적 분석 도구입니다. 실제 유효 권한, 리소스 접근 가능성 또는 권한 상승 가능성을 확정하는 정책 평가 엔진은 아닙니다.

## 주요 기능

- IAM 정책의 전체 권한 및 서비스 전체 작업 허용 탐지
- 콘솔 사용자 MFA 장치 미설정 점검
- 오래된 활성 Access Key 및 장기간 미사용 키 점검
- 사용 정보가 부족한 활성 키를 판단 불가로 구분
- 관리형 정책의 현재 기본 버전과 사용자·그룹·역할의 인라인 정책 분석
- 역할 신뢰 정책에서 전체 주체를 허용하는 구문과 조건 검토 대상 식별
- 넓은 역할 범위를 허용하는 PassRole 구문 탐지
- 사용자·그룹·역할·관리형 정책의 연결 관계 시각화
- PassRole 탐지 정책에 직접 또는 그룹을 통해 연결된 사용자·역할 추적
- 분석 제외 항목과 제외 사유 기록
- 수집 파일 간 계정 ID·파티션 일치 확인
- 실제 AWS 수집부터 보고서·관계 그래프 생성까지 명령어 하나로 실행
- 가상 데이터 기반 S3 공개 접근 설정 분석
- 자동 테스트 및 GitHub Actions 검증

## 탐지 규칙

| 규칙 | 점검 내용 | 적용 범위 |
| --- | --- | --- |
| IAM001 | Allow 구문의 Action과 Resource에 각각 값이 정확히 `*`인 항목이 있는지 확인 | 샘플·수집 권한 정책 |
| IAM002 | Allow 구문에 `s3:*`처럼 서비스 전체 작업을 허용하는 Action이 있는지 확인 | 샘플·수집 권한 정책 |
| IAM003 | 콘솔 비밀번호가 있는 IAM 사용자의 MFA 장치 미설정 확인 | 샘플·수집 사용자 |
| IAM004 | 생성 후 기준 기간 이상 지난 활성 Access Key 확인 | 샘플·수집 키 |
| IAM005 | 기준 기간 이상 사용되지 않은 활성 Access Key 확인 | 샘플·수집 키 |
| IAM006 | 역할 신뢰 정책의 `Principal: "*"` 또는 AWS 주체의 `*`와 역할 수임 작업 허용 구문 확인 | 샘플·수집 역할 신뢰 정책 |
| IAM007 | 공개 정책 상태와 Public Access Block 설정을 바탕으로 S3 검토 대상 식별 | 별도 입력 데이터 분석 |
| IAM008 | `iam:PassRole`과 일치하는 작업을 허용하면서 역할 리소스 범위에 와일드카드를 사용하는 구문 확인 | 샘플·수집 권한 정책 |

IAM004와 IAM005의 기본 기준은 각각 90일입니다. 이는 프로젝트의 기본 점검 기준이며, 모든 환경에 적용되는 의무 기준은 아닙니다.

탐지 건수는 규칙별 항목 수입니다. 동일한 정책·사용자·키가 여러 규칙에 해당하면 각각 집계될 수 있습니다.

IAM007은 별도의 S3 분석 기능입니다. 현재 IAM 수집 파이프라인은 실제 S3 설정을 수집하거나 IAM007 결과를 통합 보고서에 포함하지 않습니다.

## 실행 환경 및 설치

- Python 3.12
- 실제 AWS 수집 시 boto3 및 로컬 AWS 인증 프로필 필요
- 아래 명령어는 Windows CMD 기준

```cmd
git clone https://github.com/kjm0320/cloud-iam-analyzer.git
cd cloud-iam-analyzer
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

새 CMD를 열었을 때는 프로젝트 폴더로 이동한 뒤 가상환경을 활성화합니다.

```cmd
cd cloud-iam-analyzer
.venv\Scripts\activate
```

macOS·Linux에서는 해당 운영체제에 맞는 가상환경 활성화 명령과 파일 경로를 사용합니다. `start` 명령은 Windows용입니다.

## AWS 계정 없이 실행하는 데모

아래 데모는 가상 데이터를 사용하며 AWS API를 호출하지 않습니다.

### 1. 보안 설정 개선 전후 비교

```cmd
python run_demo.py
start "" "reports\demo\before.html"
start "" "reports\demo\after.html"
```

| 항목 | 개선 전 | 개선 후 |
| --- | ---: | ---: |
| IAM001 | 1 | 0 |
| IAM002 | 1 | 0 |
| IAM003 | 1 | 0 |
| IAM004 | 2 | 0 |
| IAM005 | 1 | 0 |
| 전체 탐지 | 6 | 0 |
| 사용 정보 판단 불가 | 1 | 0 |

가상의 개선 내용을 입력 데이터에 반영하여 비교합니다.

- 전체 권한을 샘플 버킷의 객체 읽기 권한으로 제한
- 콘솔 사용자의 MFA 설정 상태 변경
- 불필요하다고 가정한 키 2개를 비활성 상태로 변경

실제 AWS 설정을 변경하지 않습니다. 판단 불가 감소는 사용 이력을 새로 확인한 결과가 아니라, 해당 키가 비활성화되어 점검 대상에서 제외된 결과입니다.

이 데모는 IAM001~IAM005를 검증하며, 예상 결과와 다르면 오류로 종료합니다.

생성 위치:

- `samples/demo/before/`, `samples/demo/after/`
- `reports/demo/before.json`, `reports/demo/after.json`
- `reports/demo/before.html`, `reports/demo/after.html`
- `reports/demo/comparison.json`

### 2. IAM 관계 그래프

```cmd
python run_relationship_demo.py
start "" "reports\demo\relationships.html"
```

노드 5개와 연결 4개로 구성된 가상 관계를 검증하고 시각화합니다.

| 연결 종류 | 의미 | 표시 |
| --- | --- | --- |
| 그룹 소속 | 사용자와 소속 그룹의 관계 | 회색 실선 |
| 정책 연결 | 사용자·그룹·역할에 연결된 관리형 정책 | 파란색 실선 |
| 권한 경계 | 사용자·역할에 설정된 권한 경계 정책 참조 | 보라색 점선 |

권한 경계는 권한 부여 경로로 취급하지 않습니다. 가운데 열을 건너뛰는 연결선은 노드 상자 아래로 우회하여 연결 대상이 가려지는 것을 줄입니다.

생성 위치:

- `samples/relationships_demo.json`
- `reports/demo/relationships.json`
- `reports/demo/relationships.html`

### 3. PassRole 검토 대상 연결 분석

```cmd
python run_passrole_demo.py
start "" "reports\demo\passrole_relationships.html"
```

넓은 PassRole 허용 구문이 있는 관리형 정책과 연결된 사용자·역할을 관계 그래프 아래 표에 표시합니다.

데모는 탐지 구문 1개와 연결된 검토 대상 2개를 검증합니다.

| 검토 대상 | 정책 연결 경로 |
| --- | --- |
| demo-user | 그룹 경유 |
| demo-service-role | 직접 정책 연결 |

표에는 정책 이름, 구문 번호, 대상 ARN, 연결 경로, 역할 리소스 범위 및 조건을 표시합니다.

조건이 있는 구문도 검토 대상으로 표시하며, 조건이 실제로 접근을 얼마나 제한하는지는 평가하지 않습니다.

생성 위치:

- `reports/demo/passrole_relationships.json`
- `reports/demo/passrole_relationships.html`

### 4. S3 공개 접근 설정 분석

```cmd
python s3_analyzer.py samples\s3_public_access.json
python html_s3_report.py samples\s3_public_access.json --output reports\demo\s3_public_access.html
start "" "reports\demo\s3_public_access.html"
```

가상 입력의 버킷 정책 공개 상태와 계정·버킷 수준 Public Access Block 설정을 분석합니다.

공개 정책 상태와 `RestrictPublicBuckets` 설정을 바탕으로 검토 대상, 제한 설정 확인, 판단 불가 등을 구분합니다.

ACL, 액세스 포인트 및 다른 접근 제어 요소를 모두 평가하지 않으므로, 결과만으로 실제 공개 접근 가능 여부를 확정하지 않습니다.

## 실제 AWS 계정 분석

### 인증과 수집 권한

기본 프로필 이름은 `cloud-iam-analyzer`입니다. 사전에 로컬에 설정한 AWS 인증 프로필을 사용합니다.

수집기가 사용하는 IAM 조회 작업:

- `iam:GetAccountAuthorizationDetails`
- `iam:ListUsers`
- `iam:GetLoginProfile`
- `iam:ListMFADevices`
- `iam:ListAccessKeys`
- `iam:GetAccessKeyLastUsed`

추가로 STS `GetCallerIdentity`를 호출하여 수집 계정을 확인합니다.

인증 정보를 코드에 넣거나 저장소에 커밋하지 않습니다. 루트 계정의 액세스 키를 사용하지 않고, 수집에 필요한 조회 권한을 가진 자격 증명을 사용합니다.

### 실행 범위와 비용 관련 설계

실제 수집기는 IAM·STS 조회를 수행합니다.

- EC2 등 실행 자원을 생성하지 않습니다.
- IAM 정책·사용자·키를 변경하거나 삭제하지 않습니다.
- AWS IAM Access Analyzer의 유료 분석 기능을 호출하지 않습니다.
- 로컬 분석과 가상 데이터 데모는 AWS 리소스 생성 없이 실행합니다.

프로젝트 실행과 별개로 사용 중인 AWS 리소스의 비용까지 관리하거나 차단하는 기능은 없습니다.

### 전체 파이프라인 실행

```cmd
python run_aws_scan.py --profile cloud-iam-analyzer
```

실행 순서:

1. IAM 사용자 및 MFA 정보 수집
2. Access Key 메타데이터와 사용 정보 수집
3. IAM 정책 및 연결 정보 수집
4. 계정 정보 확인 및 통합 분석
5. 통합 HTML 보고서 생성
6. IAM 연결 관계 및 PassRole 검토 대상 정리
7. HTML 관계 그래프 생성

중간 단계가 실패하면 이후 단계를 실행하지 않습니다.

일부 수집 파일만 갱신되었거나 이전 보고서가 남아 있을 수 있으므로, 오류를 해결한 뒤 전체 명령어를 다시 실행합니다.

### 결과 열기

```cmd
start "" "reports\private\combined_report.html"
start "" "reports\private\relationships.html"
```

| 경로 | 내용 |
| --- | --- |
| `data/private/users.json` | 사용자 및 MFA 정보 |
| `data/private/access_keys.json` | 키 메타데이터 및 사용 정보 |
| `data/private/policies.json` | IAM 정책·사용자·그룹·역할 구성 |
| `reports/private/combined_report.json` | 통합 분석 결과 |
| `reports/private/combined_report.html` | 통합 HTML 보고서 |
| `reports/private/relationships.json` | 관계 그래프 및 PassRole 연결 검토 결과 |
| `reports/private/relationships.html` | HTML 관계 그래프 및 검토 대상 표 |

실제 수집 데이터와 보고서는 공개 저장소에 포함하지 않습니다.

## 개별 실행

### 계정 확인 및 수집

```cmd
python aws_identity.py --profile cloud-iam-analyzer
python collect_users.py --profile cloud-iam-analyzer
python collect_access_keys.py --profile cloud-iam-analyzer
python collect_policies.py --profile cloud-iam-analyzer
```

### 사용자·키 분석

```cmd
python account_analyzer.py data\private\users.json
python access_key_analyzer.py data\private\access_keys.json
python unused_key_analyzer.py data\private\access_keys.json
```

개별 키 분석의 기준 기간을 변경할 수 있습니다.

```cmd
python access_key_analyzer.py data\private\access_keys.json --max-age-days 120
python unused_key_analyzer.py data\private\access_keys.json --max-unused-days 120
```

현재 통합 분석은 기본값인 90일을 사용합니다.

### 수집 정책 및 역할 신뢰 정책 분석

```cmd
python analyze_collected_policies.py
python analyze_collected_policies.py --include-passrole
python analyze_collected_trust.py
```

개별 수집 정책 분석에서는 `--include-passrole`을 지정하여 IAM008을 포함합니다. 실제 데이터 통합 분석에서는 IAM008을 포함하도록 구성되어 있습니다.

### 통합 보고서 및 관계 그래프 생성

기존에 수집한 파일을 사용합니다.

```cmd
python scan_collected.py
python html_collected_report.py
python build_relationships.py
python html_relationships.py
```

### 단일 샘플 정책 분석

```cmd
python analyzer.py samples\admin_policy.json
python analyzer.py samples\limited_policy.json
python analyzer.py samples\service_wildcard_policy.json
python passrole_analyzer.py samples\admin_policy.json
```

## 분석 결과 해석

### 탐지·판단 불가·분석 제외

- **탐지:** 구현한 규칙에 해당하는 설정이 발견된 상태입니다.
- **판단 불가:** 사용 정보 등 판단에 필요한 데이터가 부족한 상태입니다.
- **분석 제외:** 입력 형식이나 지원 범위 등의 이유로 해당 항목을 분석하지 못한 상태입니다.

탐지 0건이어도 판단 불가와 분석 제외 항목을 함께 확인해야 합니다.

### Access Key 사용 정보

실제 AWS 수집에서 마지막 사용 시각이 없으면 `unknown`으로 저장합니다. 이를 사용한 적 없는 키로 단정하지 않습니다.

활성 키의 사용 정보가 `unknown`이면 미사용 분석에서 판단 불가로 기록합니다. 비활성 키는 IAM004·IAM005 및 미사용 판단 불가 집계에서 제외합니다.

키의 사용 기간이나 마지막 사용 시각만으로 키 유출 여부를 판단하지 않습니다.

### 권한 정책

관리형 정책은 현재 기본 버전만 분석합니다. 사용자·그룹·역할에 포함된 인라인 정책도 각각 분석합니다.

일반 권한 정책 분석에서 `NotAction`·`NotResource`는 지원하지 않으며, 해당 정책은 사유와 함께 분석 제외로 기록합니다.

정책의 Condition, 명시적 거부, SCP 및 권한 경계를 종합 평가하지 않습니다. 따라서 Allow 구문 탐지가 실제 권한 보유를 의미하지는 않습니다.

### 역할 신뢰 정책

역할 신뢰 정책은 일반 권한 정책과 분리하여 분석합니다.

전체 주체를 대상으로 역할 수임 작업을 허용하는 구문을 확인하고, 조건이 있으면 조건 검토가 필요하다고 표시합니다.

특정 외부 계정이나 서비스 주체의 신뢰가 적절한지 모두 평가하는 기능은 아니며, 실제 역할 수임 가능성을 확정하지 않습니다.

### PassRole 연결 분석

IAM008 정책 분석과 사용자·역할 연결 분석의 범위는 다릅니다.

| 기능 | 범위 |
| --- | --- |
| IAM008 정책 분석 | 분석 가능한 관리형·인라인 권한 정책의 넓은 PassRole 허용 구문 |
| PassRole 연결 분석 | 관리형 정책의 직접 연결 및 그룹 소속을 통한 사용자·역할 추적 |

PassRole 연결 분석은 다음 원칙을 사용합니다.

- 그룹에 연결된 정책은 해당 그룹의 수집된 소속 사용자까지 추적합니다.
- 권한 경계 연결을 권한 부여 경로로 계산하지 않습니다.
- 인라인 정책은 현재 연결 추적에 포함하지 않습니다.
- 연결된 대상이 있는 관리형 정책 중 분석하지 못한 정책은 별도로 기록합니다.
- 조건과 역할 리소스 범위를 검토 근거로 표시합니다.

전달 대상 역할의 실제 권한·신뢰 정책 및 서비스 작업 권한을 함께 검증하지 않으므로, 검토 대상은 확인된 권한 상승 경로가 아닙니다.

### 계정 일치 확인

수집 파일에 기록된 계정 ID·파티션과 호출자 ARN을 확인합니다. 파일 간 계정이나 파티션이 다르면 통합 분석을 중단합니다.

이 검증은 서로 다른 계정의 파일이 섞이는 문제를 줄이기 위한 장치입니다. 로컬 파일의 위변조 여부나 서로 다른 수집 시점의 일관성을 보장하지 않습니다.

## HTML 보고서

통합 보고서는 다음 정보를 제공합니다.

- 탐지·판단 불가·사용자·키 개수
- 규칙별 탐지 건수
- 탐지 대상·근거·개선 방안
- 정책 이름·기본 버전·인라인 정책 소유자
- 역할 신뢰 정책의 검토 대상과 조건 정보
- 분석 완료·제외 항목 수 및 제외 사유
- 데이터별 수집 시각과 분석 한계

관계 보고서는 노드·연결 그래프, 연결 상세 표, 확인 필요 항목 및 PassRole 검토 대상 표를 제공합니다.

보고서는 외부 웹 자원 없이 브라우저에서 열 수 있습니다. 동적 텍스트는 HTML 특수 문자를 이스케이프합니다.

관계 그래프의 색상은 연결 종류를 구분하며, 위험도 등급을 의미하지 않습니다.

## 테스트 및 GitHub Actions

전체 테스트:

```cmd
python -m unittest discover -s tests -v
```

가상 데이터 데모 검증:

```cmd
python run_demo.py
python run_relationship_demo.py
python run_passrole_demo.py
```

주요 검증 내용:

- 탐지 대상과 제외 대상
- 기간 경계와 시간대 처리
- 입력 검증과 판단 불가 처리
- AWS 응답의 페이지 처리 및 오류 전파
- 정책 기본 버전 선택과 분석 제외 처리
- 계정·파티션 불일치 거부
- 역할 신뢰 정책과 PassRole 구문 분석
- S3 공개 접근 설정 분석
- 그룹 경유 정책 연결과 권한 경계 구분
- JSON·HTML 생성 및 HTML 이스케이프
- 입력 파일 덮어쓰기 방지
- 실행 단계 실패 시 후속 단계 중단

실패 상황을 검증하는 테스트에서는 의도적으로 `[ERROR]` 메시지가 출력될 수 있습니다. 테스트 실행의 최종 `OK` 또는 `FAILED` 결과로 통과 여부를 확인합니다.

GitHub Actions는 자동 테스트와 위의 세 가지 데모를 실행합니다. CI에서는 실제 AWS에 접속하지 않으며 AWS 인증 키가 필요하지 않습니다.

## 데이터 관리

공개 저장소에는 코드와 공개용 가상 데이터를 사용합니다. 일부 데모 보고서는 저장소에 포함하지 않고 실행 시 생성합니다.

실제 계정 데이터와 보고서는 다음 경로로 분리합니다.

- `data/private/`
- `reports/private/`

인증 정보 관련 경로인 `.aws/`, `.env` 등도 Git 추적 대상에서 제외합니다.

실제 보고서에는 계정 ID, 사용자 이름, 정책 ARN, 키 ID 등이 포함될 수 있으므로 공개하지 않습니다. 비밀 액세스 키 값은 수집하거나 보고서에 저장하지 않습니다.

`.gitignore`는 이미 추적 중인 파일에는 적용되지 않습니다. 커밋 전에 다음 명령어로 변경 파일과 실제 데이터의 추적 여부를 확인합니다.

```cmd
git status --short
git ls-files -- data/private reports/private
```

두 번째 명령어는 출력이 없어야 합니다. 이는 현재 추적 상태 확인이며, 과거 커밋에 민감정보가 포함된 적이 없는지까지 검증하는 명령은 아닙니다.

## 전체 분석 한계

- 탐지 0건이 계정 전체의 안전함을 의미하지 않습니다.
- 실제 유효 권한을 계산하는 IAM 정책 평가 엔진이 아닙니다.
- 전체 AWS 정책 문법과 정책 변수의 실제 값을 평가하지 않습니다.
- Condition, 명시적 거부, SCP 및 권한 경계를 종합 평가하지 않습니다.
- MFA 장치 설정 여부와 MFA 사용 강제 여부는 다릅니다.
- 루트 계정과 IAM Identity Center 사용자는 IAM 사용자·키 점검 대상에 포함되지 않습니다.
- 관계 그래프는 수집된 설정의 연결이며 실제 역할 수임·권한 상승 경로가 아닙니다.
- 특정 역할만 허용하는 PassRole 구문도 위험할 수 있지만, IAM008은 넓은 역할 범위의 구문을 중심으로 점검합니다.
- S3 기능은 입력 데이터 분석이며 실제 S3 자동 수집은 구현하지 않았습니다.
- 여러 API를 순차 호출하므로 동일 순간의 계정 스냅샷은 아닙니다.
- 보안 설정을 자동으로 수정하거나 키를 회전·삭제하지 않습니다.

## 향후 개선

현재 구현과 구분되는 향후 개선 항목입니다.

- PassRole 연결 분석에 인라인 정책 포함
- 전달 대상 역할·신뢰 정책·서비스 작업 권한을 결합한 검토 후보 분석
- S3 설정의 읽기 전용 수집 및 보고서 연동
- 대규모 계정의 그래프 가독성 개선
- 탐지 범위 확장과 오탐·분석 제외 처리 개선

## 프로젝트 목표

누구나 가상 데이터로 결과를 재현하고, 실제 AWS 계정에도 읽기 전용으로 적용할 수 있는 보안 분석 도구를 만드는 것입니다.

탐지 결과와 분석 한계를 함께 제공하여, 결과를 과장하지 않고 검토 근거를 확인할 수 있도록 설계합니다.