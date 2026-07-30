import unittest

from scm import PanApiHandler
from scm.setup import FOLDERS_ENDPOINT, SNIPPETS_ENDPOINT, SetupTargetRequest, ensure_setup_target
from tests.test_scm_api import FakeResponse, FakeSession


class SetupTargetTests(unittest.TestCase):
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
