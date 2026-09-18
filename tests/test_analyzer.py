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


if __name__ == "__main__":
    unittest.main()
