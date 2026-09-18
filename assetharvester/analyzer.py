from __future__ import annotations

import ast
import ipaddress
import json
import re
import subprocess
import xml.etree.ElementTree as element_tree
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


URI_PATTERN = re.compile(
    r"(?P<dbms>mysql|mysqlx|mysql\+srv|postgresql|postgres|mongodb|mongodb\+srv)://"
    r"(?:(?P<user>[^:@/\s]+):(?P<secret>[^@/\s]+)@)?"
    r"(?P<host>[^/?\s`'\";:]+)(?::(?P<port>\d+))?(?:/(?P<database>[^?\s`'\";]+))?", re.I)
JDBC_PATTERN = re.compile(
    r"jdbc:(?P<dbms>mysql|postgresql|mongodb|sqlserver):/{2,3}"
    r"(?:(?P<user>[^:@/\s]+):(?P<secret>[^@/\s]+)@)?"
    r"(?P<host>[^/?\s`'\";:]+)(?::(?P<port>\d+))?(?:/(?P<database>[^?\s`'\";]+))?"
    r"(?:\?(?P<query>[^\s`'\";]+))?", re.I)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DNS_PATTERN = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.\D{2,24}\b")
SECRET_KEY = re.compile(r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)", re.I)
HOST_KEY = re.compile(r"(?:host|hostname|server|data[_ -]?source|endpoint|url|uri|dsn)", re.I)
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".xml"}
SCAN_EXTENSIONS = CONFIG_EXTENSIONS | {".py", ".js", ".jsx", ".ts", ".tsx", ".env", ".ini", ".properties", ".java", ".cs"}
DRIVERS = {
    "aiomysql": {"connect": 0, "create_pool": 0}, "mysql.connector": {"connect": 0},
    "pymysql": {"connect": 0}, "aiopg": {"connect": None}, "asyncpg": {"connect": 0, "create_pool": 0},
    "psycopg2": {"connect": None}, "pymongo": {"mongoclient": 0}, "pymssql": {"connect": 0},
    "pyodbc": {"connect": 0}, "jaydebeapi": {"connect": 0}, "peewee": {"database": None},
    "sqlalchemy": {"create_engine": 0},
}
PASSWORD_ARGUMENTS = {"password", "passwd", "pwd", "secret"}
HOST_ARGUMENTS = {"host", "hostname", "server", "data_source", "data source", "endpoint", "url", "uri", "dsn"}


@dataclass(frozen=True)
class Finding:
    method: str
    pattern: str
    database_type: str
    file: str
    line: int
    secret_name: str
    secret_preview: str
    asset: str
    confidence: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        secret_source = _source_from_evidence(self.evidence, "secret")
        asset_source = _source_from_evidence(self.evidence, "asset")
        return {
            "pattern": self.pattern,
            "method": self.method,
            "database_type": self.database_type,
            "sink": {
                "file": self.file,
                "line": self.line,
            },
            "asset": {
                "value": self.asset,
                "source": asset_source,
            },
            "secret": {
                "name": self.secret_name,
                "preview": self.secret_preview,
                "source": secret_source,
            },
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class Value:
    value: Any
    file: Path
    line: int
    name: str


def _source_from_evidence(evidence: str, kind: str) -> dict[str, Any] | None:
    match = re.search(rf"{kind} source ([^:,]+):(\d+)(?: \(([^)]+)\))?", evidence)
    if not match:
        return None
    source: dict[str, Any] = {
        "file": match.group(1),
        "line": int(match.group(2)),
    }
    if match.group(3):
        source["name"] = match.group(3)
    return source


def _preview(value: str) -> str:
    return "*" * len(value) if len(value) < 5 else f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _asset(host: str, port: str | None = None, database: str | None = None) -> str:
    return ":".join(part for part in (host, port, database) if part)


def _valid_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,24}", host))


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _dbms(value: str) -> str:
    return {"postgres": "PostgreSQL", "postgresql": "PostgreSQL", "mysql": "MySQL", "mysqlx": "MySQL", "mysql+srv": "MySQL", "mongodb": "MongoDB", "mongodb+srv": "MongoDB", "sqlserver": "SQL Server"}.get(value.lower(), value)


def _key_value_connection(value: str) -> tuple[str, str, str | None] | None:
    pairs = {key.strip().lower(): item.strip() for key, item in (segment.split("=", 1) for segment in value.split(";") if "=" in segment)}
    if not ("driver" in pairs or "provider" in pairs):
        return None
    host = pairs.get("server") or pairs.get("data source")
    secret = pairs.get("pwd") or pairs.get("password")
    return (host, secret, pairs.get("database") or pairs.get("initial catalog")) if host and secret else None


def _pattern_findings(text: str, path: Path, evidence_prefix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for match in URI_PATTERN.finditer(text):
        if match.group("secret") and _valid_host(match.group("host")):
            findings.append(Finding("pattern-matching", "P1", _dbms(match.group("dbms")), str(path), _line(text, match.start()), "connection-string-password", _preview(match.group("secret")), _asset(match.group("host"), match.group("port"), match.group("database")), "high", f"{evidence_prefix}URI connection string"))
    for match in JDBC_PATTERN.finditer(text):
        query = dict(item.split("=", 1) for item in (match.group("query") or "").split("&") if "=" in item)
        secret = match.group("secret") or query.get("password")
        if secret and _valid_host(match.group("host")):
            findings.append(Finding("pattern-matching", "P1", _dbms(match.group("dbms")), str(path), _line(text, match.start()), "jdbc-password", _preview(secret), _asset(match.group("host"), match.group("port"), match.group("database")), "high", f"{evidence_prefix}JDBC connection string"))
    for match in re.finditer(r"(?:Driver|Provider)=[^\n'\"]+", text, re.I):
        parsed = _key_value_connection(match.group(0))
        if parsed and _valid_host(parsed[0]):
            host, secret, database = parsed
            findings.append(Finding("pattern-matching", "P1", "ODBC/OLE-DB", str(path), _line(text, match.start()), "connection-string-password", _preview(secret), _asset(host, None, database), "high", f"{evidence_prefix}ODBC/OLE-DB key-value connection string"))
    return findings


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


class Repository:
    def __init__(self, root: Path):
        self.root, self.trees, self.texts, self.values, self.imports = root, {}, {}, {}, {}
        self._load()

    def _load(self) -> None:
        for path in self.root.rglob("*.py"):
            try:
                text, tree = path.read_text(encoding="utf-8"), ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (UnicodeDecodeError, SyntaxError):
                continue
            self.texts[path], self.trees[path], self.values[path], self.imports[path] = text, tree, {}, {}
        for path, tree in self.trees.items():
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and node.module:
                    module = self._module_path(path, node.module)
                    if module:
                        for item in node.names:
                            self.imports[path][item.asname or item.name] = (module, item.name)
                elif isinstance(node, ast.Assign):
                    value = self.resolve(node.value, path)
                    if value:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.values[path][target.id] = Value(value.value, value.file, value.line, target.id)

    def _module_path(self, source: Path, module: str) -> Path | None:
        candidates = [source.parent / f"{module.replace('.', '/')}.py", self.root / f"{module.replace('.', '/')}.py"]
        return next((candidate.resolve() for candidate in candidates if candidate.resolve() in self.trees), None)

    def resolve(self, node: ast.AST, path: Path) -> Value | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
            return Value(node.value, path, node.lineno, "literal")
        if isinstance(node, ast.Name):
            if node.id in self.values[path]:
                return self.values[path][node.id]
            if node.id in self.imports[path]:
                imported_path, name = self.imports[path][node.id]
                return self.values[imported_path].get(name)
        if isinstance(node, ast.JoinedStr):
            pieces: list[str] = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    pieces.append(item.value)
                elif isinstance(item, ast.FormattedValue) and (value := self.resolve(item.value, path)):
                    pieces.append(str(value.value))
                else:
                    return None
            return Value("".join(pieces), path, node.lineno, "f-string")
        if isinstance(node, ast.Dict):
            result: dict[str, Any] = {}
            for key, item in zip(node.keys, node.values):
                key_value, item_value = (self.resolve(key, path) if key else None), self.resolve(item, path)
                if not key_value or not item_value or not isinstance(key_value.value, str):
                    return None
                result[key_value.value] = item_value.value
            return Value(result, path, node.lineno, "dict")
        if isinstance(node, ast.Subscript):
            container, key = self.resolve(node.value, path), self.resolve(node.slice, path)
            if container and key and isinstance(container.value, dict) and key.value in container.value:
                return Value(container.value[key.value], container.file, container.line, str(key.value))
        return None


def _driver(call: ast.Call) -> tuple[str, int | None] | None:
    name = _qualified_name(call.func).lower()
    for driver, functions in DRIVERS.items():
        for function, position in functions.items():
            if name.endswith(f"{driver}.{function}") or name == function:
                return driver, position
    return None


def _dataflow_findings(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for path, tree in repository.trees.items():
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not (driver := _driver(call)):
                continue
            name, host_position = driver
            arguments: dict[str, Value] = {}
            for keyword in call.keywords:
                value = repository.resolve(keyword.value, path)
                if keyword.arg and value:
                    arguments[keyword.arg.lower()] = value
                elif not keyword.arg and value and isinstance(value.value, dict):
                    arguments.update({key.lower(): Value(item, value.file, value.line, key) for key, item in value.value.items()})
            secret_name, secret = next(((key, value) for key, value in arguments.items() if key in PASSWORD_ARGUMENTS and isinstance(value.value, str)), ("", None))
            if not secret:
                for argument in call.args:
                    candidate = repository.resolve(argument, path)
                    if candidate and isinstance(candidate.value, str) and SECRET_KEY.search(candidate.name):
                        secret_name, secret = candidate.name, candidate
                        break
            host = next((value for key, value in arguments.items() if key in HOST_ARGUMENTS and isinstance(value.value, (str, int))), None)
            if not host and host_position is not None and len(call.args) > host_position:
                host = repository.resolve(call.args[host_position], path)
            if not secret or not host:
                continue
            host_text = str(host.value)
            uri = URI_PATTERN.search(host_text) or JDBC_PATTERN.search(host_text)
            if uri:
                host_text = uri.group("host")
            if not _valid_host(host_text):
                continue
            port = next((str(value.value) for key, value in arguments.items() if key == "port"), None)
            database = next((str(value.value) for key, value in arguments.items() if key in {"database", "db", "dbname"}), None)
            pattern = "P2" if secret.line == call.lineno and host.line == call.lineno else ("P4" if secret.file != path or host.file != path else "P3")
            findings.append(Finding("static-value-flow", pattern, name, str(path), call.lineno, secret_name, _preview(str(secret.value)), _asset(host_text, port, database), "high", f"{name} sink; secret source {secret.file.name}:{secret.line}, asset source {host.file.name}:{host.line}"))
    return findings


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, f"{prefix}.{key}" if prefix else str(key))
    else:
        yield prefix, value


def _simple_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, result)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        indent, (key, value) = len(raw) - len(raw.lstrip()), raw.strip().split(":", 1)
        while stack[-1][0] >= indent:
            stack.pop()
        current = stack[-1][1]
        if value.strip():
            current[key.strip()] = value.strip().strip("'\"")
        else:
            current[key.strip()] = {}
            stack.append((indent, current[key.strip()]))
    return result


def _parse_config(path: Path) -> tuple[dict[str, Any], str] | None:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return json.loads(text), text
        if path.suffix.lower() in {".yaml", ".yml"}:
            return _simple_yaml(text), text
        return {child.tag: child.text or "" for child in element_tree.parse(path).getroot()}, text
    except (UnicodeDecodeError, ValueError, element_tree.ParseError):
        return None


def _literal_string(node: ast.AST, repository: Repository, path: Path) -> str | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        right = _literal_string(node.right, repository, path)
        if right:
            return right
    value = repository.resolve(node, path)
    return str(value.value) if value and isinstance(value.value, str) else None


def _config_path(source: Path, filename: str) -> Path | None:
    candidate = (source.parent / filename).resolve()
    return candidate if candidate.suffix.lower() in CONFIG_EXTENSIONS and candidate.is_file() else None


def _config_bindings(repository: Repository, source: Path) -> dict[str, Path]:
    handles: dict[str, Path] = {}
    bindings: dict[str, Path] = {}
    tree = repository.trees[source]
    nodes = sorted(ast.walk(tree), key=lambda node: getattr(node, "lineno", 0))
    for node in nodes:
        if isinstance(node, ast.With):
            for item in node.items:
                context = item.context_expr
                if isinstance(context, ast.Call) and isinstance(item.optional_vars, ast.Name):
                    path_node = None
                    if _qualified_name(context.func) == "open" and context.args:
                        path_node = context.args[0]
                    elif isinstance(context.func, ast.Attribute) and context.func.attr == "open":
                        path_node = context.func.value
                    filename = _literal_string(path_node, repository, source) if path_node else None
                    if filename and (config := _config_path(source, filename)):
                        handles[item.optional_vars.id] = config
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        target, value = node.targets[0].id, node.value
        if isinstance(value, ast.Call) and value.args:
            if isinstance(value.args[0], ast.Name) and value.args[0].id in handles and _qualified_name(value.func).endswith(("safe_load", ".load")):
                bindings[target] = handles[value.args[0].id]
        elif isinstance(value, ast.Call) and _qualified_name(value.func).endswith("getroot") and isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Call):
            parse_call = value.func.value
            if _qualified_name(parse_call.func).endswith("parse") and parse_call.args:
                filename = _literal_string(parse_call.args[0], repository, source)
                if filename and (config := _config_path(source, filename)):
                    bindings[target] = config
    return bindings


def _subscript_reference(node: ast.AST, bindings: dict[str, Path], repository: Repository, source: Path) -> tuple[Path, list[str]] | None:
    keys: list[str] = []
    current = node
    while isinstance(current, ast.Subscript):
        key = _literal_string(current.slice, repository, source)
        if key is None:
            return None
        keys.insert(0, key)
        current = current.value
    if isinstance(current, ast.Name) and current.id in bindings:
        return bindings[current.id], keys
    return None


def _config_reference(node: ast.AST, bindings: dict[str, Path], repository: Repository, source: Path) -> tuple[Path, list[str]] | None:
    reference = _subscript_reference(node, bindings, repository, source)
    if reference:
        return reference
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "findtext" and isinstance(node.func.value, ast.Name) and node.func.value.id in bindings and node.args:
        key = _literal_string(node.args[0], repository, source)
        if key:
            return bindings[node.func.value.id], [key]
    return None


def _config_value(path: Path, keys: list[str]) -> Value | None:
    parsed = _parse_config(path)
    if not parsed:
        return None
    data, text = parsed
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if not isinstance(current, (str, int)):
        return None
    line = next((index + 1 for index, line_text in enumerate(text.splitlines()) if keys[-1] in line_text), 1)
    return Value(current, path, line, ".".join(keys))


def _config_key_flow_findings(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for source, tree in repository.trees.items():
        bindings = _config_bindings(repository, source)
        if not bindings:
            continue
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not (driver := _driver(call)):
                continue
            driver_name, _ = driver
            arguments: dict[str, Value] = {}
            for keyword in call.keywords:
                if keyword.arg and (reference := _config_reference(keyword.value, bindings, repository, source)) and (value := _config_value(*reference)):
                    arguments[keyword.arg.lower()] = value
            secret_name, secret = next(((key, value) for key, value in arguments.items() if key in PASSWORD_ARGUMENTS), ("", None))
            host_name, host = next(((key, value) for key, value in arguments.items() if key in HOST_ARGUMENTS), ("", None))
            if not secret or not host or not _valid_host(str(host.value)):
                continue
            findings.append(Finding("config-key-data-flow", "P4", driver_name, str(source), call.lineno, secret_name, _preview(str(secret.value)), str(host.value), "high", f"{driver_name} sink; config source {secret.file.name}; secret source {secret.file.name}:{secret.line} ({secret.name}), asset source {host.file.name}:{host.line} ({host.name})"))
    return findings


JS_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<value>[^;\n]+)"
)
JS_POOL_PATTERN = re.compile(
    r"(?:mysql|mysql2)\.createPool\s*\(\s*\{(?P<body>.*?)\}\s*\)", re.S
)
JS_PROPERTY_PATTERN = re.compile(
    r"\b(?P<name>host|hostname|server|password|passwd|pwd|database|db)\s*:\s*(?P<value>[^,\n}]+)"
)
ENV_REFERENCE_PATTERN = re.compile(r"process\.env\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)")


def _javascript_dataflow_findings(root: Path) -> list[Finding]:
    env_values: dict[str, Value] = {}
    for env_path in root.rglob("*.env"):
        try:
            env_text = env_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(env_text.splitlines(), 1):
            match = re.match(r"\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)\s*$", line)
            if match and match.group("value"):
                env_values[match.group("name")] = Value(match.group("value").strip("'\""), env_path, line_number, match.group("name"))

    findings: list[Finding] = []
    for source in root.rglob("*"):
        if not source.is_file() or source.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        bindings: dict[str, Value] = {}
        for assignment in JS_ASSIGNMENT_PATTERN.finditer(text):
            raw_value = assignment.group("value").strip()
            env_match = ENV_REFERENCE_PATTERN.fullmatch(raw_value)
            if env_match:
                env_name = env_match.group("name")
                bindings[assignment.group("name")] = env_values.get(
                    env_name,
                    Value(f"env:{env_name}", source, _line(text, assignment.start()), f"env:{env_name}"),
                )
            elif len(raw_value) >= 2 and raw_value[0] in "'\"`" and raw_value[-1] == raw_value[0]:
                bindings[assignment.group("name")] = Value(raw_value[1:-1], source, _line(text, assignment.start()), assignment.group("name"))

        for pool in JS_POOL_PATTERN.finditer(text):
            arguments: dict[str, Value] = {}
            for property_match in JS_PROPERTY_PATTERN.finditer(pool.group("body")):
                raw_value = property_match.group("value").strip()
                env_match = ENV_REFERENCE_PATTERN.fullmatch(raw_value)
                if env_match:
                    env_name = env_match.group("name")
                    value = env_values.get(env_name, Value(f"env:{env_name}", source, _line(text, pool.start()), f"env:{env_name}"))
                elif raw_value in bindings:
                    value = bindings[raw_value]
                elif len(raw_value) >= 2 and raw_value[0] in "'\"`" and raw_value[-1] == raw_value[0]:
                    value = Value(raw_value[1:-1], source, _line(text, pool.start()), property_match.group("name"))
                else:
                    continue
                arguments[property_match.group("name").lower()] = value
            secret_name, secret = next(((name, value) for name, value in arguments.items() if name in PASSWORD_ARGUMENTS), ("", None))
            host_name, host = next(((name, value) for name, value in arguments.items() if name in HOST_ARGUMENTS), ("", None))
            if not secret or not host:
                continue
            host_value = str(host.value)
            if not _valid_host(host_value) and not host_value.startswith("env:"):
                continue
            findings.append(Finding(
                "javascript-data-flow",
                "P3",
                "mysql2",
                str(source),
                _line(text, pool.start()),
                secret_name,
                _preview(str(secret.value)),
                host_value,
                "high" if not host_value.startswith("env:") else "medium",
                f"mysql2.createPool sink; secret source {secret.file.name}:{secret.line} ({secret.name}), asset source {host.file.name}:{host.line} ({host.name})",
            ))
    return findings


def jaro_winkler(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    window, left_matches, right_matches, matches = max(len(left), len(right)) // 2 - 1, [False] * len(left), [False] * len(right), 0
    for index, char in enumerate(left):
        for candidate in range(max(0, index - window), min(index + window + 1, len(right))):
            if not right_matches[candidate] and char == right[candidate]:
                left_matches[index] = right_matches[candidate] = True
                matches += 1
                break
    if not matches:
        return 0.0
    transpositions = sum(first != second for first, second in zip((char for index, char in enumerate(left) if left_matches[index]), (char for index, char in enumerate(right) if right_matches[index]))) / 2
    jaro, prefix = (matches / len(left) + matches / len(right) + (matches - transpositions) / matches) / 3, 0
    for first, second in zip(left, right):
        if first != second or prefix == 4:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro)


def _neighbor_findings(text: str, path: Path, excluded: set[int], window: int = 3) -> list[Finding]:
    findings: list[Finding] = []
    assignment = re.compile(r"^\s*(?:#\s*)?(?P<name>[A-Za-z_]\w*)\s*=\s*['\"](?P<value>[^'\"]+)['\"]")
    lines = text.splitlines()
    for index, line in enumerate(lines):
        secret = assignment.match(line)
        if not secret or not SECRET_KEY.search(secret.group("name")) or index + 1 in excluded:
            continue
        candidates: list[tuple[str, str]] = []
        for nearby in lines[max(0, index - window):min(len(lines), index + window + 1)]:
            name = re.match(r"\s*(?:#\s*)?(?P<name>[A-Za-z_]\w*)\s*=", nearby)
            for host in IP_PATTERN.findall(nearby) + DNS_PATTERN.findall(nearby):
                if _valid_host(host):
                    candidates.append((name.group("name") if name else "asset", host))
        if candidates:
            asset_name, asset_value = max(candidates, key=lambda candidate: jaro_winkler(secret.group("name"), candidate[0]))
            score = jaro_winkler(secret.group("name"), asset_name)
            if score >= 0.5:
                findings.append(Finding("neighboring-lines", "P3", "heuristic", str(path), index + 1, secret.group("name"), _preview(secret.group("value")), asset_value, "medium", f"±{window} lines; Jaro-Winkler={score:.2f} with {asset_name}"))
    return findings


def _history_findings(root: Path) -> list[Finding]:
    if not (root / ".git").exists():
        return []
    revisions = subprocess.run(["git", "-C", str(root), "rev-list", "--all"], capture_output=True, check=False)
    if revisions.returncode:
        return []
    findings: list[Finding] = []
    for revision in filter(None, revisions.stdout.decode("utf-8", errors="replace").splitlines()):
        changed = subprocess.run(["git", "-C", str(root), "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", revision], capture_output=True, check=False)
        for relative_path in filter(None, changed.stdout.decode("utf-8", errors="replace").splitlines()):
            if Path(relative_path).suffix.lower() not in SCAN_EXTENSIONS:
                continue
            content = subprocess.run(["git", "-C", str(root), "show", f"{revision}:{relative_path}"], capture_output=True, check=False)
            if content.returncode == 0:
                findings.extend(_pattern_findings(content.stdout.decode("utf-8", errors="replace"), root / relative_path, f"commit {revision[:12]}; "))
    return findings


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique = {(item.method, item.file, item.line, item.secret_preview, item.asset): item for item in findings}
    return sorted(unique.values(), key=lambda item: (item.file, item.line, item.method))


def analyze_path(target: str | Path, history: bool = False) -> list[Finding]:
    path = Path(target).resolve()
    root = path if path.is_dir() else path.parent
    repository, findings = Repository(root), []
    for file_path in sorted(item for item in root.rglob("*") if item.is_file() and item.suffix.lower() in SCAN_EXTENSIONS):
        try:
            findings.extend(_pattern_findings(file_path.read_text(encoding="utf-8"), file_path))
        except UnicodeDecodeError:
            continue
    findings.extend(_dataflow_findings(repository))
    findings.extend(_config_key_flow_findings(repository))
    findings.extend(_javascript_dataflow_findings(root))
    excluded: dict[Path, set[int]] = {}
    for finding in findings:
        excluded.setdefault(Path(finding.file), set()).add(finding.line)
        source = re.search(r"secret source ([^:]+):(\d+)", finding.evidence)
        if source:
            for file_path in repository.texts:
                if file_path.name == source.group(1):
                    excluded.setdefault(file_path, set()).add(int(source.group(2)))
    for file_path, text in repository.texts.items():
        findings.extend(_neighbor_findings(text, file_path, excluded.get(file_path, set())))
    if history:
        findings.extend(_history_findings(root))
    return _deduplicate(findings)
