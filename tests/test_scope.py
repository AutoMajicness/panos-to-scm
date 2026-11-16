import unittest

from scm.scope import Scope


class ScopeTests(unittest.TestCase):
    def test_folder_scope_param_to_query_params(self):
        scope = Scope.from_param("&folder=All")

        self.assertEqual(scope.as_query_params(), {"folder": "All"})

    def test_snippet_scope_applies_to_payload(self):
        scope = Scope.from_param("&snippet=Shared")

        payload = scope.apply_to_payload({"name": "addr", "folder": "Old", "fqdn": "example.com"})

        self.assertEqual(payload, {"name": "addr", "fqdn": "example.com", "snippet": "Shared"})

    def test_invalid_scope_type_fails(self):
        with self.assertRaises(ValueError):
            Scope.from_param("&tenant=All")

    def test_multiple_scopes_fail(self):
        with self.assertRaises(ValueError):
            Scope.from_param("&folder=All&snippet=Shared")


if __name__ == "__main__":
    unittest.main()
