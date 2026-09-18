from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from .analyzer import analyze_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate AssetHarvester secret-asset pair detection.")
    parser.add_argument("target", nargs="?", default="cases", help="File or directory to analyze")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    parser.add_argument("--output", type=Path, help="Write JSON findings to this file; default is a timestamped outputs directory")
    parser.add_argument("--output-dir", type=Path, help="Write JSON findings under this shared directory")
    parser.add_argument("--history", action="store_true", help="Also inspect Git history for connection strings")
    arguments = parser.parse_args()
    if arguments.output and arguments.output_dir:
        parser.error("--output and --output-dir cannot be used together")
    target = Path(arguments.target)
    findings = analyze_path(target, history=arguments.history)
    if arguments.json:
        payload = json.dumps([finding.to_dict() for finding in findings], ensure_ascii=False, indent=2)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = arguments.output or (arguments.output_dir or Path("outputs") / timestamp) / f"{target.name}-findings.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {output}")
        return 0
    print(f"AssetHarvester simulation: {len(findings)} secret-asset pair observations")
    for finding in findings:
        print(f"[{finding.method}/{finding.pattern}/{finding.confidence}] {finding.file}:{finding.line} {finding.secret_name}={finding.secret_preview} -> {finding.asset} ({finding.evidence})")
    counts = Counter(finding.method for finding in findings)
    print("Methods: " + ", ".join(f"{method}={count}" for method, count in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
