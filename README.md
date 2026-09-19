# AssetHarvester Simulation 기술 명세서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 프로젝트 | AssetHarvester Simulation |
| 목적 | 소프트웨어 artifact에서 secret-asset pair를 정적 분석으로 탐지 |
| 참고 논문 | ICSE 2025 AssetHarvester |
| 구현 언어 | Python |
| 지원 분석 대상 | Python, JavaScript, TypeScript, Java, C#, 설정 파일 |
| 실행 환경 | Windows PowerShell 기준 |
| 외부 접속 | 분석 대상 애플리케이션·DB는 실행하지 않음 |

## 2. 목표

본 프로젝트는 데이터베이스 연결 정보 주변의 secret과 asset을 함께 탐지하는 연구용 프로토타입이다.

- secret만 찾는 것이 아니라 secret이 보호하는 asset까지 함께 제시한다.
- 연결문자열과 분리된 변수 흐름을 모두 분석한다.
- 현재 소스뿐 아니라 Git commit history도 분석할 수 있다.
- 공개 GitHub repository를 내려받아 반복적으로 비교 실험할 수 있다.
- 출력 결과에서 원문 secret은 마스킹한다.

## 3. 디렉터리 구조

```text
assetharvester/
├─ assetharvester/
│  ├─ analyzer.py              # 핵심 분석기
│  └─ cli.py                   # CLI 진입점
├─ cases/                      # 논문 패턴 재현용 실제형 fixture
│  ├─ case01_connection_strings/
│  ├─ case02_same_line/
│  ├─ case03_data_flow/
│  ├─ case04_cross_module/
│  ├─ case05_config_flow/
│  ├─ case06_neighboring_lines/
│  ├─ case07_driver_catalog/
│  ├─ case08_global_flow/
│  └─ case09_javascript_env_flow/
├─ codeql/
│  └─ queries/                 # Python CodeQL query
├─ scripts/
│  ├─ run_codeql.ps1
│  └─ render_captures.py
├─ targets/
│  ├─ 2024_DDV/                # 외부 GitHub 분석 대상
│  └─ public-repo/              # 공개 repository 실험 대상
├─ tests/
├─ outputs/
│  ├─ codeql/
│  └─ YYYYMMDD_HHMMSS/         # 실행별 JSON 결과
└─ docs/
```

## 4. 분석 파이프라인

```text
입력 경로
   ↓
지원 확장자 파일 수집
   ↓
Pattern Matching
   ↓
Python AST static value flow
   ↓
YAML/JSON/XML config key flow
   ↓
Neighboring-line heuristic
   ↓
선택적 Git history scan
   ↓
Finding deduplication
   ↓
JSON / SARIF / 콘솔 출력
```

## 5. 탐지 방식

### 5.1 Pattern Matching

핵심 정규식은 `assetharvester/analyzer.py`에 정의되어 있다.

| 패턴 | 대상 |
|---|---|
| `URI_PATTERN` | MySQL, PostgreSQL, MongoDB URI |
| `JDBC_PATTERN` | JDBC MySQL/PostgreSQL/MongoDB/SQL Server URL |
| ODBC/OLE-DB matcher | `Driver=`, `Provider=`, `Server=`, `Password=` 형식 |
| `IP_PATTERN` | IPv4 주소 |
| `DNS_PATTERN` | 도메인 후보 |
| `SECRET_KEY` | password, secret, token, api key 등 변수명 |
| `HOST_KEY` | host, server, endpoint, url, uri 등 asset 변수명 |

정규식 단계는 파일 내용 기반이므로 Python·JavaScript·TypeScript·Java·C# 등 지원 확장자에서는 언어 문법과 무관하게 동작한다.

탐지 가능한 예:

```javascript
const url = "mysql://user:password@db.example.com:3306/orders";
```

탐지하지 못하는 대표 예:

```javascript
mysql.createPool({
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD
});
```

위 사례는 실제 값이 환경변수에 있으므로 JavaScript data-flow 모델이 별도로 필요하다.

### 5.2 Python static value flow

Python AST 기반 분석은 다음을 지원한다.

- 문자열 상수
- f-string
- dictionary와 `**kwargs`
- positional argument
- 단순 import 상수
- DB driver keyword sink
- 일부 driver의 positional sink

현재 지원 driver catalog에는 `aiomysql`, `mysql.connector`, `pymysql`, `aiopg`, `asyncpg`, `psycopg2`, `pymongo`, `pymssql`, `pyodbc`, `jaydebeapi`, `peewee`, `sqlalchemy`가 포함된다.

### 5.3 JavaScript environment data flow

JavaScript·TypeScript 파일의 `mysql2.createPool({...})` 호출을 sink로 모델링하고, 다음 source를 연결한다.

- `process.env.DB_HOST`, `process.env.DB_PASSWORD` 등의 환경변수 참조
- 같은 파일의 단순 변수 alias
- 해당 소스 파일 또는 상위 디렉토리의 `.env`에 정의된 literal 값

예를 들어 다음 코드는 `javascript-data-flow/P3` finding을 생성한다.

```javascript
mysql.createPool({
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD
});
```

`.env` 파일이 없으면 asset은 `env:DB_HOST`처럼 환경변수 provenance로 기록하고 confidence를 `medium`으로 낮춘다. `.env`에서 값을 찾으면 source 파일을 기록하고 P4로 분류한다.

### 5.4 Configuration key flow

Python 코드에서 다음 형식의 설정값 사용을 추적한다.

- YAML: `yaml.safe_load(...)`
- JSON: `json.load(...)`
- XML: `ElementTree.parse(...).getroot()` 및 `findtext(...)`

설정 파일의 host/password key가 같은 DB sink에 전달되고 host와 secret이 모두 유효하면 `config-key-data-flow/P4` finding을 생성한다.

### 5.5 Neighboring-line heuristic

secret 변수 주변 ±3줄의 IP/DNS 후보를 수집하고 Jaro–Winkler similarity로 asset 후보를 선택한다.

이 방식은 빠르지만 변수명 유사성에 의존하므로 false positive가 발생할 수 있다. 결과 confidence는 `medium`으로 기록한다.

### 5.6 Git history

`--history` 옵션을 사용하면 다음 Git 명령을 기반으로 과거 snapshot을 검사한다.

```text
git rev-list --all
git diff-tree --root --name-only -r <commit>
git show <commit>:<path>
```

history finding에는 commit 앞 12자리와 원본 파일 line을 evidence에 기록한다. Git 출력은 UTF-8 기준으로 안전하게 decode하며, 지원 확장자만 대상으로 한다.

## 6. 지원 파일 확장자

현재 텍스트 분석 대상은 다음과 같다.

```text
.py .js .jsx .ts .tsx .java .cs
.json .yaml .yml .xml
.env .ini .properties
```

AST와 CodeQL은 현재 Python 중심이다. 다른 언어는 Pattern Matching 단계 중심으로 분석된다.

## 7. 실행 방법

모든 명령은 프로젝트 루트에서 실행한다.

### 7.1 샘플 cases 분석

```powershell
python -m assetharvester.cli cases
```

JSON 출력:

```powershell
python -m assetharvester.cli cases --json --output outputs\cases-findings.json
```

Git history 포함:

```powershell
python -m assetharvester.cli cases --history --json --output outputs\cases-history-findings.json
```

### 7.2 단일 외부 repository 분석

```powershell
python -m assetharvester.cli targets\2024_DDV --history --json --output outputs\2024_DDV-findings.json
```

분석 대상 repository 코드는 실행하지 않는다.

### 7.3 공개 repository 여러 개 분석

사전에 `targets/public-repo/` 아래에 repository를 clone한 후 실행한다.

```powershell
$runDir = Join-Path outputs (Get-Date -Format yyyyMMdd_HHmmss)
New-Item -ItemType Directory -Force $runDir | Out-Null

Get-ChildItem targets\public-repo -Directory | ForEach-Object {
    python -m assetharvester.cli $_.FullName --json --output-dir $runDir
    Write-Host "$($_.Name) scanned"
}
```

모든 repository 결과가 하나의 `outputs\YYYYMMDD_HHMMSS\` 디렉토리 안에 저장된다. 단일 실행에서 `--output-dir`를 생략하면 CLI가 실행 시각 디렉토리를 자동 생성한다.

### 7.4 CodeQL 실행

기본 소스 루트는 `cases/`이며 `run_codeql.ps1` 위치를 기준으로 경로가 계산된다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_codeql.ps1
```

특정 하위 경로:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_codeql.ps1 `
  -SourceRoot cases\case08_global_flow
```

현재 query는 Python용이다. JavaScript/TypeScript repository에 실행하면 Python source가 없다는 이유로 CodeQL 결과가 생성되지 않는다.

## 8. 출력 형식

### Finding schema

```json
{
  "pattern": "P1",
  "method": "pattern-matching",
  "database_type": "PostgreSQL",
  "sink": {"file": "path/to/file.py", "line": 42},
  "asset": {"value": "db.example.com:5432:orders", "source": null},
  "secret": {"name": "connection-string-password", "preview": "fa********rd", "source": null},
  "confidence": "high"
}
```

data flow finding에는 `asset.source`와 `secret.source`에 전체 파일 경로·라인·변수명을 기록한다. preview는 원문 secret이 아니라 앞·뒤 일부와 마스킹 문자로 구성된다.

### CodeQL SARIF

기본 출력:

```text
outputs/codeql/secret-asset-flow.sarif
```

현재 query:

- `SecretAssetFlow.ql`: local-flow baseline
- `GlobalSecretAssetFlow.ql`: global interprocedural flow

## 9. 검증 현황

### 내부 fixture

```text
Python unittest: 17 tests passed
CodeQL queries: 2 compiled/evaluated
JavaScript mysql2 environment flow: verified
```

### 공개 repository 실험

최근 10개 공개 repository 실험 결과:

- 총 탐지: 44건
- P1 connection string: 27건
- P3 static value flow: 8건
- neighboring-line: 9건
- 주로 테스트 코드·문서용 connection string에서 탐지

상세 결과:

```text
outputs/PUBLIC_REPO_SCAN_REPORT.md
outputs/public-repo-scan-results.json
```

## 10. 현재 한계

- JavaScript/TypeScript data-flow는 현재 `mysql2.createPool`과 환경변수·단순 alias 범위만 지원한다.
- Java/C#의 AST data-flow는 아직 구현되지 않았다.
- `process.env.DB_PASSWORD`, `.env` 로딩 등 runtime secret source 흐름은 제한적이다.
- CodeQL query가 Python으로 고정되어 있다.
- shallow clone 실험에서는 전체 history를 분석하지 않는다.
- neighboring-line heuristic은 테스트 코드와 일반 token 변수에서 false positive를 만들 수 있다.
- secret 유효성 검증이나 실제 DB/API 접속은 수행하지 않는다.
- 원문 secret을 결과에 저장하지 않지만, 운영 환경에서는 출력 파일 권한과 보존 기간을 별도로 관리해야 한다.

## 11. 권장 다음 작업

1. JavaScript/TypeScript AST 또는 CodeQL 분석 추가
2. `mysql2.createPool`, `mongoose.connect`, `sequelize` sink 모델 추가
3. `process.env.*` 및 `.env` source 모델 추가
4. GitHub App/webhook 기반 incremental scan 추가
5. full history scan과 PR diff scan 분리
6. finding deduplication 및 first-seen/last-seen 상태 저장
7. SARIF 업로드를 통한 GitHub Code Scanning 연동

## 12. 보안 운영 원칙

- 외부 repository 코드는 실행하지 않는다.
- `npm install`, `pip install`, 빌드, 테스트 실행을 자동으로 수행하지 않는다.
- 분석 대상의 secret 원문을 콘솔·Markdown·JSON에 기록하지 않는다.
- private repository 분석 시 token을 clone URL에 직접 포함하지 않는다.
- 분석 결과 파일을 공유할 때 파일 권한과 보존 기간을 확인한다.
