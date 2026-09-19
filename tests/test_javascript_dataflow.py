import tempfile
import unittest
from pathlib import Path

from assetharvester.analyzer import analyze_path


class JavaScriptDataFlowTests(unittest.TestCase):
    def test_environment_sources_reach_mysql2_pool_sink(self) -> None:
        root = Path(__file__).resolve().parents[1] / "cases" / "case09_javascript_env_flow"
        findings = analyze_path(root)
        self.assertEqual(1, len(findings))
        self.assertEqual("javascript-data-flow", findings[0].method)
        self.assertEqual("env:DB_HOST", findings[0].asset)
        self.assertNotIn("DB_PASSWORD", findings[0].secret_preview)

    def test_environment_values_stay_with_their_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, host in (("one", "one.example.com"), ("two", "two.example.com")):
                project = root / name
                project.mkdir()
                (project / ".env").write_text(
                    f"DB_HOST={host}\nDB_PASSWORD=sample-password\n",
                    encoding="utf-8",
                )
                (project / "app.js").write_text(
                    "const mysql = require('mysql2');\n"
                    "const pool = mysql.createPool({host: process.env.DB_HOST, password: process.env.DB_PASSWORD});\n",
                    encoding="utf-8",
                )
            findings = [item for item in analyze_path(root) if item.method == "javascript-data-flow"]
        self.assertEqual(2, len(findings))
        self.assertEqual({"one.example.com", "two.example.com"}, {item.asset for item in findings})
        self.assertEqual({"P4"}, {item.pattern for item in findings})
        self.assertEqual({"high"}, {item.confidence for item in findings})


if __name__ == "__main__":
    unittest.main()
