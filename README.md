\# Cloud IAM Analyzer



AWS IAM 정책에서 보안 위험 후보를 탐지하는 Python 정적 분석기입니다.

가상의 정책 파일로 로컬에서 실행하며, AWS 계정이나 인증 정보가 필요하지 않습니다.



\## 구현된 기능



| 규칙 | 탐지 대상 |

|---|---|

| IAM001 | Allow 구문의 Action과 Resource에 각각 전체 범위 `\*`가 포함된 경우 |

| IAM002 | Allow 구문에 `s3:\*`처럼 서비스 전체 작업을 허용하는 Action이 포함된 경우 |



\- Statement의 단일 객체·배열 형식 지원

\- Action과 Resource의 문자열·배열 형식 지원

\- Condition이 있는 탐지 결과에 추가 검토 표시

\- 터미널 결과 출력 및 JSON 보고서 저장

\- 입력 파일과 동일한 경로로 보고서 저장 방지

\- 자동 테스트 10개 및 GitHub Actions 연동



IAM002는 Resource가 제한되어 있어도 서비스 전체 작업 허용을 검토 대상으로 표시합니다.

탐지 결과는 규칙에 해당하는 Statement 단위로 생성됩니다.



\## 실행 환경



\- Python 3.12 기준 GitHub Actions 테스트

\- 외부 Python 패키지 설치 불필요



\## 실행 방법



저장소 루트에서 실행합니다.



```bat

python analyzer.py samples\\admin\_policy.json

```



예상 결과: IAM001 1건.



```bat

python analyzer.py samples\\limited\_policy.json

```



예상 결과: 0건.



```bat

python analyzer.py samples\\service\_wildcard\_policy.json

```



예상 결과: IAM002 1건.



위 명령어는 Windows CMD 기준입니다.

macOS와 Linux에서는 경로 구분자 `\\`를 `/`로 바꿔 실행합니다.



\## JSON 보고서 저장



```bat

python analyzer.py samples\\service\_wildcard\_policy.json --output reports\\service\_wildcard\_report.json

```



출력 폴더가 없으면 자동으로 생성합니다.

기존 출력 파일이 있으면 덮어씁니다.



보고서에는 다음 항목이 포함됩니다.



\- 보고서 형식 버전

\- 입력 파일 이름

\- 탐지 건수

\- 규칙 ID, Statement 번호, Sid, 탐지 설명, Condition 존재 여부

\- 분석 한계



\## 테스트



```bat

python -m unittest discover -s tests -v

```



현재 테스트 10개로 탐지 규칙과 JSON 보고서 저장 기능을 검증합니다.

GitHub Actions에서 push와 pull request마다 테스트를 실행합니다.



\## 프로젝트 구조



```text

cloud-iam-analyzer/

├── .github/

│   └── workflows/

│       └── tests.yml

├── samples/

│   ├── admin\_policy.json

│   ├── limited\_policy.json

│   └── service\_wildcard\_policy.json

├── reports/

│   └── service\_wildcard\_report.json

├── tests/

│   ├── test\_analyzer.py

│   └── test\_report.py

├── analyzer.py

├── .gitignore

└── README.md

```



\## 분석 한계



\- 현재 IAM001과 IAM002 규칙만 구현되어 있습니다.

\- 전체 AWS IAM 정책 문법을 검증하지 않습니다.

\- 실제 유효 권한과 Condition 충족 여부를 평가하지 않습니다.

\- 다른 Statement나 정책의 Deny, 권한 경계, SCP 등을 종합 평가하지 않습니다.

\- NotAction과 NotResource를 이용한 권한 표현은 분석하지 않습니다.

\- 탐지 0건이 안전함을 의미하지 않습니다.

\- 현재 AWS 계정에 연결하거나 실제 리소스를 변경하지 않습니다.



\## 데이터 관리



공개 저장소에는 가상의 샘플 데이터와 해당 분석 결과만 포함합니다.



실제 계정 데이터를 다루게 되면 다음 경로를 사용합니다.

이 경로는 .gitignore에 등록되어 있습니다.



\- data/private/: 실제 계정 데이터

\- reports/private/: 비공개 분석 결과



인증 정보는 코드나 보고서에 포함하지 않습니다.

.gitignore는 이미 Git이 추적하는 파일에는 적용되지 않으므로

커밋 전 변경 내용을 확인합니다.



\## 향후 개발 목표



\- 입력 검증 강화

\- MFA 및 Access Key 상태 점검

\- 리소스 공개 접근 가능성 점검

\- 권한 상승 후보 경로 분석 및 관계 시각화

\- 위험도와 개선 방안을 포함한 HTML 보고서

\- 비용이 발생하지 않는 범위를 확인한 뒤 AWS 읽기 전용 연동

