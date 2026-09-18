from __future__ import annotations

import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".tools" / "python-deps"))

from PIL import Image, ImageDraw, ImageFont
from assetharvester.analyzer import Finding, analyze_path


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"
DESTINATION = ROOT / "docs" / "captures"


def source_text(names: list[str]) -> list[str]:
    lines: list[str] = []
    for name in names:
        lines.append(f"$ {name}")
        lines.extend((CASES / name).read_text(encoding="utf-8").splitlines())
        lines.append("")
    return lines


def finding_text(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["(no findings)"]
    return [
        f"[{finding.method}/{finding.pattern}] {Path(finding.file).name}:{finding.line}  {finding.secret_preview} -> {finding.asset}"
        for finding in findings
    ]


def write_capture(name: str, title: str, sources: list[str], findings: list[Finding], results: list[str] | None = None) -> None:
    source_lines = source_text(sources)
    result_lines = results if results is not None else finding_text(findings)
    displayed = source_lines + ["RESULTS"] + result_lines
    width, line_height, padding = 1500, 25, 42
    height = max(290, padding * 2 + line_height * (len(displayed) + 3))
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0f172a"/>',
        f'<text x="{padding}" y="42" fill="#e2e8f0" font-family="Segoe UI, sans-serif" font-size="24" font-weight="700">{html.escape(title)}</text>',
    ]
    y = 82
    for line in displayed:
        colour = "#fbbf24" if line == "RESULTS" else "#93c5fd" if line.startswith("$") else "#e2e8f0"
        elements.append(f'<text x="{padding}" y="{y}" fill="{colour}" font-family="Consolas, monospace" font-size="16">{html.escape(line)}</text>')
        y += line_height
    elements.append("</svg>")
    (DESTINATION / name).write_text("\n".join(elements), encoding="utf-8")
    image = Image.new("RGB", (width, height), "#0f172a")
    draw = ImageDraw.Draw(image)
    title_font = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 24)
    body_font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 16)
    draw.text((padding, 20), title, fill="#e2e8f0", font=title_font)
    y = 62
    for line in displayed:
        colour = "#fbbf24" if line == "RESULTS" else "#93c5fd" if line.startswith("$") else "#e2e8f0"
        draw.text((padding, y), line, fill=colour, font=body_font)
        y += line_height
    image.save(DESTINATION / f"{Path(name).stem}.png")


def main() -> None:
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for stem in ("07-codeql-sarif", "08-codeql-sarif", "09-codeql-sarif"):
        for suffix in (".png", ".svg"):
            (DESTINATION / f"{stem}{suffix}").unlink(missing_ok=True)
    findings = analyze_path(CASES)
    groups = [
        ("01-pattern-1.svg", "Case 1 — P1: connection-string pattern matching", ["case01_connection_strings/app.py"], lambda item: Path(item.file).parent.name == "case01_connection_strings"),
        ("02-pattern-2.svg", "Case 2 — P2: separate strings on one call line", ["case02_same_line/webhook_handler.py"], lambda item: Path(item.file).parent.name == "case02_same_line"),
        ("03-pattern-3-data-flow.svg", "Case 3 — P3: separate lines, CodeQL-style data flow", ["case03_data_flow/orders_repository.py"], lambda item: Path(item.file).parent.name == "case03_data_flow"),
        ("04-pattern-4-import.svg", "Case 4 — P4: values from an application settings module", ["case04_cross_module/settings.py", "case04_cross_module/inventory_repository.py"], lambda item: Path(item.file).parent.name == "case04_cross_module"),
        ("05-pattern-4-config.svg", "Case 5 — P4: YAML, JSON, and XML configuration parsing", ["case05_config_flow/config.yaml", "case05_config_flow/config.json", "case05_config_flow/config.xml", "case05_config_flow/app.py"], lambda item: Path(item.file).parent.name == "case05_config_flow"),
        ("06-neighboring-lines.svg", "Case 6 — fast approximation with Jaro-Winkler selection", ["case06_neighboring_lines/health_check.py"], lambda item: Path(item.file).parent.name == "case06_neighboring_lines"),
        ("07-driver-catalog.svg", "Case 7 — all 12 Python database drivers from Table III", ["case07_driver_catalog/adapters.py"], lambda item: Path(item.file).parent.name == "case07_driver_catalog"),
        ("08-global-flow.svg", "Case 8 — interprocedural global data flow", ["case08_global_flow/service.py"], lambda item: Path(item.file).parent.name == "case08_global_flow"),
    ]
    for name, title, sources, predicate in groups:
        write_capture(name, title, sources, [item for item in findings if predicate(item)])
    sarif = ROOT / "outputs" / "codeql" / "secret-asset-flow.sarif"
    if sarif.exists():
        results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0].get("results", [])
        rendered = [f"{result['locations'][0]['physicalLocation']['artifactLocation']['uri']}:{result['locations'][0]['physicalLocation']['region']['startLine']}  {result['message']['text']}" for result in results]
        write_capture("09-codeql-sarif.svg", "Case 9 — actual CodeQL SARIF output", [], [], rendered)


if __name__ == "__main__":
    main()
