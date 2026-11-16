import json
import tempfile
import unittest
from pathlib import Path

from tools.smoke_real_configs import run_smoke, write_report


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "panos"


class SmokeRealConfigsTests(unittest.TestCase):
    def test_run_smoke_writes_sanitized_summary_without_payloads(self):
        report = run_smoke(
            [FIXTURE_DIR / "local_policy_reference_variants.xml"],
            strict_local_firewall=True,
            fail_on_blockers=True,
        )

        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["summary"]["configs"], 1)
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["summary"]["blockers"], 0)
        result = report["results"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["validation_summary"]["warnings"], 0)
        self.assertIn("security_pre_rules", result["parsed_object_counts"])
        self.assertEqual(result["remediation"], [])
        self.assertNotIn("creates", result)
        self.assertNotIn("warnings", result)

    def test_write_report_creates_parent_directory(self):
        report = {"summary": {"configs": 0}, "results": []}

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "nested" / "smoke.json"

            write_report(report, output_path)

            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
