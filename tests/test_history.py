import subprocess
import tempfile
import unittest
from pathlib import Path

from assetharvester.analyzer import analyze_path


class HistoryScanningTests(unittest.TestCase):
    def test_history_finding_has_commit_provenance_and_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
            (root / "app.py").write_text('URI = "postgresql://demo:fake-history-password@history.demo.internal:5432/audit"\n', encoding="utf-8")
            subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True)
            findings = analyze_path(root, history=True)
        history_finding = next(item for item in findings if "commit " in item.evidence)
        self.assertEqual(1, history_finding.line)
        self.assertEqual("history.demo.internal:5432:audit", history_finding.asset)
