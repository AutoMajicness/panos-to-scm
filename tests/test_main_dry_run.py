import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from config import AppConfig


class MainDryRunTests(unittest.TestCase):
    def test_dry_run_writes_plan_output_with_current_data(self):
        parsed_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10"},
                {"name": "changed", "ip_netmask": "192.0.2.20"},
            ]
        }
        current_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10", "folder": "All"},
                {"name": "changed", "ip_netmask": "192.0.2.21"},
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            parsed_path = directory_path / "parsed.json"
            current_path = directory_path / "current.json"
            output_path = directory_path / "plan.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")
            current_path.write_text(json.dumps(current_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Address",
                    json_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                    current_data_file=str(current_path),
                    plan_output=str(output_path),
                )

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(plan.summary()["skips"], 1)
        self.assertEqual(plan.summary()["conflicts"], 1)
        self.assertEqual(report["summary"]["skips"], 1)
        self.assertEqual(report["summary"]["conflicts"], 1)
        self.assertEqual(report["skips"][0]["name"], "same")
        self.assertEqual(report["conflicts"][0]["name"], "changed")

    def test_dry_run_requires_scope_without_interactive(self):
        parsed_data = {"Address": [{"name": "addr", "ip_netmask": "192.0.2.10"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("builtins.input") as input_mock:
                with self.assertRaises(SystemExit):
                    main.main(AppConfig(), json_file=str(parsed_path), dry_run=True)

        input_mock.assert_not_called()

    def test_config_file_json_source_works_for_dry_run(self):
        parsed_data = {"Address": [{"name": "addr", "ip_netmask": "192.0.2.10"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Address",
                    config_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                )

        self.assertEqual(plan.summary()["creates"], 1)

    def test_cisco_parser_can_be_selected_without_detection_prompt(self):
        cisco_config = "\n".join(
            [
                "ASA Version 9.18",
                "hostname asa1",
                "object network WEB",
                " host 192.0.2.10",
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            cisco_path = Path(directory) / "cisco.txt"
            cisco_path.write_text(cisco_config, encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO), patch("builtins.input") as input_mock:
                plan = main.main(
                    AppConfig(),
                    parser_type="cisco",
                    config_file=str(cisco_path),
                    run_objects="Address",
                    dry_run=True,
                    scope="folder:All",
                )

        input_mock.assert_not_called()
        self.assertEqual(plan.summary()["creates"], 1)


if __name__ == "__main__":
    unittest.main()
