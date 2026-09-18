from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .analyzer import analyze_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate AssetHarvester secret-asset pair detection.")
    parser.add_argument("target", nargs="?", default="cases", help="File or directory to analyze")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    parser.add_argument("--history", action="store_true", help="Also inspect Git history for connection strings")
    arguments = parser.parse_args()
    target = Path(arguments.target)
    findings = analyze_path(target, history=arguments.history)
    if arguments.json:
        print(json.dumps([finding.to_dict() for finding in findings], ensure_ascii=False, indent=2))
        return 0
    print(f"AssetHarvester simulation: {len(findings)} secret-asset pair observations")
    for finding in findings:
        print(f"[{finding.method}/{finding.pattern}/{finding.confidence}] {finding.file}:{finding.line} {finding.secret_name}={finding.secret_preview} -> {finding.asset} ({finding.evidence})")
    counts = Counter(finding.method for finding in findings)
    print("Methods: " + ", ".join(f"{method}={count}" for method, count in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
