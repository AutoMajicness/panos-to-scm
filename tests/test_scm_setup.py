import unittest

from main import collect_device_inventory
from scm import PanApiHandler
from scm.setup import (
    FOLDERS_ENDPOINT,
    SNIPPETS_ENDPOINT,
    SetupTargetRequest,
    ensure_setup_target,
    resolve_folder_hierarchy,
    resolve_folder_snippets,
)
from tests.test_scm_api import FakeResponse, FakeSession


class SetupTargetTests(unittest.TestCase):
    def test_collect_device_inventory_paginates_and_filters_folder_hierarchy(self):
        class DeviceSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                self.get_calls.append({"url": url, "params": params, "timeout": timeout})
                if params.get("offset") == 0:
                    return FakeResponse(200, {"data": [
                        {"id": "d1", "display_name": "fw1", "serial_number": "s1", "folder": "PA-440"},
                        {"id": "d2", "display_name": "other", "serial_number": "s2", "folder": "Other"},
                    ]})
                return FakeResponse(200, {"data": []})

        inventory, failures = collect_device_inventory(
            PanApiHandler(DeviceSession()),
            folder_resolution={
                "folder_names": ["CSM-PA440"],
                "folder_ids": ["root"],
                "descendant_folders": [{"path": "CSM-PA440/PA-440", "folder_names": ["CSM-PA440", "PA-440"], "folder_ids": ["root", "fw1"]}],
            },
            limit=2,
        )

        self.assertEqual(["fw1"], [row["display_name"] for row in inventory])
        self.assertEqual([], failures)

    def test_resolve_folder_hierarchy_disambiguates_duplicate_names_by_path(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [
                    {"id": "root", "name": "CSM-PA440", "parent": "ngfw-shared"},
                    {"id": "fw1", "name": "PA-440", "parent": "root"},
                    {"id": "fw2-parent", "name": "PA-440", "parent": "root"},
                    {"id": "leaf", "name": "PA-440", "parent": "fw2-parent", "snippets": ["fw2-net"]},
                ]})

        handler = PanApiHandler(FolderSession())
        result = resolve_folder_hierarchy(handler, folder_path="CSM-PA440/PA-440/PA-440")

        self.assertEqual(result["folder_ids"], ["root", "fw2-parent", "leaf"])
        self.assertEqual(result["path"], "CSM-PA440/PA-440/PA-440")

    def test_resolve_folder_hierarchy_accepts_virtual_all_firewalls_root(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [
                    {"id": "customer", "name": "CSM-PA440", "parent": "ngfw-shared"},
                ]})

        result = resolve_folder_hierarchy(
            PanApiHandler(FolderSession()),
            folder_path="All Firewalls/CSM-PA440",
        )

        self.assertEqual(result["path"], "CSM-PA440")
        self.assertEqual(result["folder_ids"], ["customer"])

    def test_resolve_folder_hierarchy_returns_descendants_for_parent_selection(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [
                    {"id": "root", "name": "CSM-PA440", "parent": "ngfw-shared", "snippets": ["global"]},
                    {"id": "fw1", "name": "PA-440", "parent": "root", "snippets": ["fw1-net"]},
                    {"id": "fw2-parent", "name": "PA-440", "parent": "root", "snippets": ["fw2-global"]},
                    {"id": "fw2", "name": "PA-440", "parent": "fw2-parent", "snippets": ["fw2-net"]},
                ]})

        result = resolve_folder_hierarchy(
            PanApiHandler(FolderSession()),
            folder_path="All Firewalls/CSM-PA440",
        )

        self.assertEqual(
            [item["path"] for item in result["descendant_folders"]],
            ["CSM-PA440", "CSM-PA440/PA-440", "CSM-PA440/PA-440", "CSM-PA440/PA-440/PA-440"],
        )

    def test_effective_scope_uses_selected_path_ancestors_not_descendants(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [
                    {"id": "root", "name": "Customer", "parent": "ngfw-shared", "snippets": ["global-network"]},
                    {"id": "leaf", "name": "Firewall", "parent": "root", "snippets": ["firewall-network"]},
                    {"id": "child", "name": "Child", "parent": "leaf", "snippets": ["child-network"]},
                ]})

        from main import resolve_folder_scope
        result = resolve_folder_scope(
            PanApiHandler(FolderSession()),
            folder_path="Customer/Firewall",
        )

        self.assertEqual(["Customer", "Firewall"], [item["source_name"] for item in result["scope_nodes"] if item["source_type"] == "folder"])
        self.assertEqual(["global-network", "firewall-network"], result["snippet_names"])
        self.assertNotIn("child-network", result["snippet_names"])

    def test_resolve_folder_hierarchy_rejects_ambiguous_noninteractive_name(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [
                    {"id": "root", "name": "CSM-PA440", "parent": "ngfw-shared"},
                    {"id": "fw1", "name": "PA-440", "parent": "root"},
                    {"id": "fw2", "name": "PA-440", "parent": "root"},
                ]})

        with self.assertRaisesRegex(ValueError, "ambiguous"):
            resolve_folder_hierarchy(PanApiHandler(FolderSession()), folder_name="PA-440")

    def test_resolve_folder_snippets_preserves_priority_order(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                self.get_calls.append({"url": url, "params": params, "timeout": timeout})
                return FakeResponse(200, {"data": [{
                    "id": "folder-id",
                    "name": "FW1",
                    "snippets": [
                        {"name": "low", "priority": 10},
                        {"name": "high", "priority": 20},
                    ],
                }]})

        result = resolve_folder_snippets(PanApiHandler(FolderSession()), "FW1")

        self.assertEqual(result["snippet_names"], ["high", "low"])
        self.assertEqual(result["folder"]["snippets"][0]["name"], "low")

    def test_resolve_folder_snippets_accepts_name_list_and_deduplicates(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [{"name": "FW1", "snippets": ["base", "base", "override"]}]})

        result = resolve_folder_snippets(PanApiHandler(FolderSession()), "FW1")

        self.assertEqual(result["snippet_names"], ["base", "override"])

    def test_resolve_folder_snippets_requires_association(self):
        class FolderSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                return FakeResponse(200, {"data": [{"name": "FW1", "snippets": []}]})

        result = resolve_folder_snippets(PanApiHandler(FolderSession()), "FW1")

        self.assertEqual(result["snippet_names"], [])

    def test_setup_target_reports_missing_without_create(self):
        session = FakeSession()
        session.get_response = FakeResponse(200, {"data": []})
        handler = PanApiHandler(session)

        result = ensure_setup_target(
            handler,
            SetupTargetRequest(folder_name="FW1", snippet_name="FW1-network", create=False),
        )

        self.assertFalse(result["summary"]["ready"])
        self.assertEqual(result["summary"]["missing"], ["snippet", "folder"])
        self.assertEqual(session.post_calls, [])

    def test_setup_target_treats_404_lookup_as_missing(self):
        session = FakeSession()
        session.get_response = FakeResponse(
            404,
            {"_errors": [{"message": "Resource not present"}]},
            "Resource not present",
        )
        handler = PanApiHandler(session)

        result = ensure_setup_target(
            handler,
            SetupTargetRequest(folder_name="FW1", snippet_name="FW1-network", create=False),
        )

        self.assertFalse(result["summary"]["ready"])
        self.assertEqual(result["summary"]["missing"], ["snippet", "folder"])

    def test_setup_target_creates_missing_snippet_and_folder(self):
        session = FakeSession()
        session.get_response = FakeResponse(200, {"data": []})
        handler = PanApiHandler(session)

        result = ensure_setup_target(
            handler,
            SetupTargetRequest(folder_name="FW1", snippet_name="FW1-network", parent_folder="All", create=True),
        )

        self.assertTrue(result["summary"]["ready"])
        self.assertEqual(
            [call["url"] for call in session.post_calls],
            [
                f"https://api.strata.paloaltonetworks.com{SNIPPETS_ENDPOINT}",
                f"https://api.strata.paloaltonetworks.com{FOLDERS_ENDPOINT}",
            ],
        )
        self.assertEqual(session.post_calls[1]["json"]["snippets"], ["FW1-network"])
        self.assertEqual(result["scopes"]["network_scope"], "snippet:FW1-network")

    def test_setup_target_uses_existing_resources(self):
        class SetupSession(FakeSession):
            def get(self, url, params=None, timeout=20):
                self.get_calls.append({"url": url, "params": params, "timeout": timeout})
                if url.endswith("/snippets"):
                    return FakeResponse(200, {"data": [{"id": "snippet-id", "name": "FW1-network"}]})
                return FakeResponse(200, {"data": [{"id": "folder-id", "name": "FW1", "parent": "All"}]})

        session = SetupSession()
        handler = PanApiHandler(session)

        result = ensure_setup_target(
            handler,
            SetupTargetRequest(folder_name="FW1", snippet_name="FW1-network", create=True),
        )

        self.assertTrue(result["summary"]["ready"])
        self.assertEqual(session.post_calls, [])
        self.assertEqual(result["resources"]["folder"]["id"], "folder-id")
        self.assertEqual(result["resources"]["snippet"]["id"], "snippet-id")


if __name__ == "__main__":
    unittest.main()
