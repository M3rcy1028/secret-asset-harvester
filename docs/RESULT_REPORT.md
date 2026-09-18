# AssetHarvester 시뮬레이션 결과보고서

## 1. 요약

본 보고서는 ICSE 2025 연구 논문 *AssetHarvester: A Static Analysis Tool for Detecting Secret-Asset Pairs in Software Artifacts*의 핵심 탐지 아이디어를 `assetharvester/` 폴더에서 재현하고, 공식 GitHub 구현과 비교한 뒤 보완 구현을 검증한 결과를 기록한다.

검증 대상은 실제 자격증명이나 외부 시스템이 아니라 `cases/`의 안전한 테스트 fixture다. 모든 비밀값은 `fake-*` 형태이며 분석 출력에는 원문 비밀값을 기록하지 않는다.

### 최종 결과

| 항목 | 결과 |
|---|---:|
| Python 회귀 테스트 | 8개 전체 통과 |
| CodeQL 쿼리 | 2개 컴파일·평가 성공 |
| SARIF 결과 | 54건 |
| 전역 함수 경계 흐름 | `cases/case08_global_flow/service.py`에서 확인 |
| 설정 파일 흐름 | YAML·JSON·XML 모두 확인 |
| 지원 driver catalog | 논문 Table III 기준 12개 |

## 2. 공식 구현과의 비교

공식 저장소는 다음 세 영역을 중심으로 구성된다.

1. Pattern Matching: URI, ODBC/OLE-DB, JDBC 계열 정규식 탐지
2. Data Flow Analysis: CodeQL query를 이용한 DB driver sink 분석
3. Fast Approximation: IP/DNS와 secret 후보의 근접도 기반 pair 추정

이번 시뮬레이션은 공식 구현의 핵심 흐름을 유지하면서 다음 부족한 부분을 보완했다.

| 비교 항목 | 공식 구현 관찰 | 보완 구현 |
|---|---|---|
| 정규식 | 논문 그룹의 연결문자열 탐지 | URI·ODBC/OLE-DB·JDBC fixture와 마스킹 출력 검증 |
| Data Flow | CodeQL sink 및 local 흐름 중심 | local query와 `TaintTracking::Global` query를 함께 실행 |
| 함수 경계 | 제한된 흐름 모델 | 별도 함수 인자가 `pymysql.connect`에 도달하는 사례 추가 |
| Config | CodeQL query 중심 | YAML·JSON·XML key를 실제 DB 호출 인자까지 추적 |
| Driver 지원 | CodeQL 모델에 의존 | Table III의 12개 Python driver catalog와 AST sink 모델 추가 |
| History | 커밋/변경 분석 활용 | 모든 reachable commit snapshot을 검사하고 commit id를 evidence에 보존 |
| 안전한 결과 | 원문 노출 가능성 주의 필요 | 모든 `secret_preview`를 마스킹하고 실제 접속을 수행하지 않음 |

## 3. 구현 내용

### 3.1 Python 분석기

`assetharvester/analyzer.py`는 다음 분석 단계를 제공한다.

- Pattern matching: 3개 연결문자열 그룹에서 secret, host, port, database 추출
- Static value flow: 상수, f-string, dictionary, positional argument, import 상수 추적
- Config key flow: YAML·JSON·XML 파일의 key 값과 DB sink 인자 연결
- Neighboring-line heuristic: ±3줄 후보를 Jaro–Winkler로 선택
- History scan: Git의 모든 reachable commit snapshot에 pattern matching 적용
- Secret masking: 결과에 원문 비밀값 대신 preview만 기록

정적 값 흐름과 CodeQL 결과는 구분한다. Python 보완기의 method 이름은 `static-value-flow`이며, 실제 CodeQL 결과는 SARIF의 `secret-asset-flow`와 `global-secret-asset-flow` rule로 기록된다.

### 3.2 CodeQL

다음 두 query를 실행한다.

- `codeql/queries/SecretAssetFlow.ql`: local-flow 기준선
- `codeql/queries/GlobalSecretAssetFlow.ql`: `TaintTracking::Global` 기반 전역 흐름

두 query는 `semmle.python.ApiGraphs`로 database driver의 credential, host, server, DSN/URI sink를 모델링한다. 전역 query는 함수 호출 경계를 넘는 흐름과 Table III driver의 대표적인 positional·keyword sink를 추가로 다룬다.

## 4. fixture별 검증

| Fixture | 검증 내용 | 결과 |
|---|---|---|
| `case01_connection_strings/app.py` | MySQL·PostgreSQL·MongoDB URI, ODBC/OLE-DB, JDBC | 7개 P1 탐지 |
| `case02_same_line/webhook_handler.py` | 같은 호출 줄의 keyword와 dictionary 값 | 통과 |
| `case03_data_flow/orders_repository.py` | 다른 줄의 상수와 DB sink | 통과 |
| `case06_neighboring_lines/health_check.py` | 가까운 후보 중 variable prefix 유사 host 선택 | 통과 |
| `case04_cross_module/` | 다른 Python 모듈의 import 상수 | 통과 |
| `case05_config_flow/` | YAML·JSON·XML key 값의 DB sink 전달 | 3개 P4 탐지 |
| `case07_driver_catalog/adapters.py` | 논문 Table III의 12개 driver 입력 형태 | 통과 |
| `case08_global_flow/service.py` | 별도 함수 인자의 global source→sink 흐름 | CodeQL global query에서 확인 |

## 5. 재현 및 검증 방법

실행 위치는 프로젝트 루트인 `assetharvester/`다.

### Python 테스트

```powershell
python -m unittest discover -s tests -v
```

검증 결과:

```text
Ran 8 tests ... OK
```

### CodeQL 실행

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_codeql.ps1
```

출력 파일:

```text
outputs/codeql/secret-asset-flow.sarif
```

검증 결과:

```text
2 queries compiled and evaluated successfully
54 SARIF results
case08_global_flow/service.py global-flow result present
case05_config_flow/app.py configuration-flow result present
```

### 캡처 생성

```powershell
python scripts\render_captures.py
```

생성되는 주요 결과는 `docs/captures/01-pattern-1.png`부터 `docs/captures/09-codeql-sarif.png`까지다.

## 6. 결과 해석

이번 결과는 논문의 Precision 97%, Recall 90%, F1 94%를 재현한 것이 아니다. 공식 AssetBench 전체 데이터셋과 동일한 실험 환경을 사용하지 않았고, 현재 결과는 교육·연구용 fixture에 대한 기능 검증이다.

SARIF 결과 수는 두 CodeQL query의 결과 합계다. 따라서 같은 source-sink 관계가 local query와 global query에서 각각 보고될 수 있으며, 이 숫자를 고유 secret-asset pair 개수로 해석하면 안 된다.

Python AST 결과는 실제 pair 관점에서 host와 credential을 함께 재구성한다. 반면 CodeQL SARIF는 sink 도달 여부와 역할을 검증하는 결과이므로, 두 출력은 상호 보완적으로 사용한다.

## 7. 한계

- 동적 import, reflection, runtime environment 변수, 암호화·복호화 이후 값은 완전하게 추적하지 않는다.
- Driver별 version-specific signature와 모든 optional argument를 완전하게 모델링하지 않았다.
- 설정 파일 key의 복잡한 alias, 배열, 사용자 정의 loader는 현재 범위 밖이다.
- Git history 분석은 저장소에 실제 Git history가 있을 때만 의미 있는 결과를 제공한다.
- 외부 시스템 연결이나 credential 유효성 검사는 의도적으로 수행하지 않는다.

## 8. 결론

보완 구현은 공식 AssetHarvester의 pattern matching, CodeQL data flow, fast approximation이라는 구조를 유지하면서, 함수 경계를 넘는 global data flow, YAML·JSON·XML 설정 key flow, 12개 driver catalog, Git history provenance, secret masking을 추가했다.

최종적으로 Python 테스트 8개와 CodeQL 2개 query 실행을 모두 통과했으며, 결과는 `outputs/codeql/secret-asset-flow.sarif`와 `docs/captures/`에서 재현할 수 있다.
