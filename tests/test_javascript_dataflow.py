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


if __name__ == "__main__":
    unittest.main()
