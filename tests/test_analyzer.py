import tempfile
import unittest
from pathlib import Path

from assetharvester.analyzer import analyze_path


class AssetHarvesterSimulationTests(unittest.TestCase):
    def test_detects_each_simulated_approach(self) -> None:
        source = '''
import mysql.connector
URI = "mysql://user:demo-password@db.demo.internal:3306/orders"
HOST = "10.20.30.40"
PASSWORD = "simulated-password"
connection = mysql.connector.connect(host=HOST, password=PASSWORD)
API_ENDPOINT = "api.demo.internal"
API_SECRET = "nearby-only-secret"
'''
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "app.py"
            file_path.write_text(source, encoding="utf-8")
            findings = analyze_path(file_path)
        methods = {finding.method for finding in findings}
        self.assertTrue({"pattern-matching", "static-value-flow", "neighboring-lines"}.issubset(methods))
        self.assertTrue(any(finding.asset == "db.demo.internal:3306:orders" for finding in findings))
        self.assertTrue(any(finding.asset == "10.20.30.40" and finding.method == "static-value-flow" for finding in findings))

    def test_masks_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "app.py"
            file_path.write_text('URI = "postgres://user:actual-secret@db.example.com/app"', encoding="utf-8")
            findings = analyze_path(file_path)
        self.assertTrue(findings)
        self.assertNotIn("actual-secret", findings[0].secret_preview)

    def test_file_target_does_not_report_sibling_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app.py"
            sibling = root / "sibling.py"
            target.write_text("URI = 'mysql://user:sample@one.example.com/app'", encoding="utf-8")
            sibling.write_text("URI = 'mysql://user:sample@two.example.com/app'", encoding="utf-8")
            findings = analyze_path(target)
        self.assertEqual(1, len(findings))
        self.assertEqual(str(target), findings[0].file)

    def test_missing_target_raises_instead_of_scanning_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                analyze_path(Path(directory) / "missing.py")

    def test_imported_sources_keep_full_paths_regardless_of_load_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "core"
            source_dir.mkdir()
            sink = source_dir / "app.py"
            settings = source_dir / "settings.py"
            sink.write_text(
                "import pymysql\nfrom settings import HOST, PASSWORD\n"
                "connection = pymysql.connect(host=HOST, password=PASSWORD)\n",
                encoding="utf-8",
            )
            settings.write_text(
                "HOST = 'db.example.com'\nPASSWORD = 'sample-password'\n",
                encoding="utf-8",
            )
            finding = next(item for item in analyze_path(root) if item.method == "static-value-flow")
        result = finding.to_dict()
        self.assertEqual(str(settings), result["asset"]["source"]["file"])
        self.assertEqual(str(settings), result["secret"]["source"]["file"])
        self.assertEqual("HOST", result["asset"]["source"]["name"])

    def test_only_recognized_driver_calls_are_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "app.py"
            source.write_text(
                "from pymysql import connect as db_connect\n"
                "HOST = 'db.example.com'\nPASSWORD = 'sample-password'\n"
                "def connect(host, password):\n    return None\n"
                "first = db_connect(host=HOST, password=PASSWORD)\n"
                "second = connect(host=HOST, password=PASSWORD)\n",
                encoding="utf-8",
            )
            findings = [item for item in analyze_path(source) if item.method == "static-value-flow"]
        self.assertEqual(1, len(findings))
        self.assertEqual(6, findings[0].line)
        self.assertEqual("pymysql", findings[0].database_type)


if __name__ == "__main__":
    unittest.main()
