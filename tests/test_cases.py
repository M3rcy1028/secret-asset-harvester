import unittest
from pathlib import Path

from assetharvester.analyzer import DRIVERS, analyze_path


CASES = Path(__file__).resolve().parents[1] / "cases"


class PaperCaseCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.findings = analyze_path(CASES)

    def test_pattern_one_covers_all_three_connection_string_groups(self) -> None:
        pattern_one = [item for item in self.findings if item.pattern == "P1" and Path(item.file).parent.name == "case01_connection_strings"]
        self.assertEqual(7, len(pattern_one))
        self.assertEqual({"MySQL", "PostgreSQL", "MongoDB", "ODBC/OLE-DB", "SQL Server"}, {item.database_type for item in pattern_one})

    def test_patterns_two_three_and_four_have_high_confidence_data_flow_findings(self) -> None:
        data_flow = [
            item
            for item in self.findings
            if item.method in {"static-value-flow", "config-key-data-flow"}
        ]
        self.assertTrue({"P2", "P3", "P4"}.issubset({item.pattern for item in data_flow}))

    def test_config_formats_and_neighboring_line_selection_are_covered(self) -> None:
        config_findings = [item for item in self.findings if item.method == "config-key-data-flow"]
        config_sources = "\n".join(item.evidence for item in config_findings)
        self.assertIn("config.yaml", config_sources)
        self.assertIn("config.json", config_sources)
        self.assertIn("config.xml", config_sources)
        neighbor = next(item for item in self.findings if Path(item.file).parent.name == "case06_neighboring_lines" and item.secret_name == "password")
        self.assertEqual("mysql-health.demo.internal:health", neighbor.asset)

    def test_secret_previews_do_not_expose_fixture_values(self) -> None:
        self.assertTrue(all("fake-" not in item.secret_preview for item in self.findings))

    def test_driver_catalog_matches_all_twelve_table_three_drivers(self) -> None:
        expected = {"aiomysql", "mysql.connector", "pymysql", "aiopg", "asyncpg", "psycopg2", "pymongo", "pymssql", "pyodbc", "jaydebeapi", "peewee", "sqlalchemy"}
        self.assertEqual(expected, set(DRIVERS))
        self.assertTrue(any(Path(item.file).parent.name == "case07_driver_catalog" for item in self.findings))
