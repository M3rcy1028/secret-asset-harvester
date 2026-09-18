import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assetharvester.analyzer import Finding
from assetharvester.cli import main


class JsonOutputTests(unittest.TestCase):
    def test_finding_json_uses_structured_sources(self) -> None:
        finding = Finding(
            "static-value-flow",
            "P4",
            "pymysql",
            "main.py",
            26,
            "PASSWORD",
            "mo******le",
            "127.0.0.1:3306",
            "high",
            "pymysql sink; secret source config.py:8 (PASSWORD), asset source config.py:5 (HOST)",
        )

        result = finding.to_dict()

        self.assertEqual(result["sink"], {"file": "main.py", "line": 26})
        self.assertEqual(result["asset"]["source"], {"file": "config.py", "line": 5, "name": "HOST"})
        self.assertEqual(result["secret"]["source"], {"file": "config.py", "line": 8, "name": "PASSWORD"})
        self.assertNotIn("evidence", result)

    def test_default_json_output_uses_timestamp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.py"
            target.write_text("URI = 'mysql://user:secret@db.example.com/app'", encoding="utf-8")
            with patch("assetharvester.cli.Path", wraps=Path):
                with patch("assetharvester.cli.datetime") as clock:
                    clock.now.return_value.strftime.return_value = "20260918_120000"
                    with patch("builtins.print"):
                        with patch("assetharvester.cli.Path.cwd", return_value=Path(directory)):
                            self.assertEqual(main_args([str(target), "--json"]), 0)
            output = Path("outputs") / "20260918_120000" / "sample.py-findings.json"
            self.assertTrue(output.exists())
            self.assertTrue(json.loads(output.read_text(encoding="utf-8")))
            output.unlink()
            output.parent.rmdir()


def main_args(arguments: list[str]) -> int:
    import sys

    with patch.object(sys, "argv", ["assetharvester", *arguments]):
        return main()


if __name__ == "__main__":
    unittest.main()
