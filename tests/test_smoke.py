
import json
import tempfile
import unittest
from pathlib import Path

from analysis_core import detect_type, basic_analysis
from export_pseudocode import export_pseudocode


class TestREA(unittest.TestCase):

    def test_python_file_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "sample.py"
            file.write_text("x = 1\n", encoding="utf-8")

            self.assertEqual(detect_type(file), "source")

    def test_python_ast_symbols(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "sample.py"
            file.write_text(
                "class Demo:\n"
                "    def hello(self):\n"
                "        return 1\n",
                encoding="utf-8",
            )

            result = basic_analysis(file)
            names = {x["name"] for x in result["symbols"]}

            self.assertIn("Demo", names)
            self.assertIn("hello", names)

    def test_pseudocode_export(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = folder / "functions.jsonl"
            output = folder / "output.c"

            records = [
                {
                    "name": "FUN_00401000",
                    "address": "00401000",
                    "pseudocode": "int func(void) { return 1; }",
                    "code_truncated": False,
                },
                {
                    "name": "FUN_00402000",
                    "address": "00402000",
                    "pseudocode": None,
                    "code_truncated": False,
                },
            ]

            source.write_text(
                "\n".join(json.dumps(x) for x in records) + "\n",
                encoding="utf-8",
            )

            result = export_pseudocode(source, output)
            code = output.read_text(encoding="utf-8")

            self.assertEqual(result["total"], 2)
            self.assertEqual(result["decompiled"], 1)
            self.assertEqual(result["missing"], 1)
            self.assertIn("FUN_00401000", code)
            self.assertIn("return 1;", code)

    def test_corrupt_jsonl_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = folder / "functions.jsonl"
            output = folder / "output.c"

            source.write_text(
                "not-valid-json\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                export_pseudocode(source, output)

            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
