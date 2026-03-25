import unittest

from backend.engine import generate_assessment, normalize_status


class TestBackendEngine(unittest.TestCase):
    def test_normalize_status(self):
        self.assertEqual(normalize_status("In Progress"), "In Progress")
        self.assertEqual(normalize_status("deferred"), "Deferred")
        self.assertEqual(normalize_status("unknown"), "In Progress")

    def test_generate_assessment_from_table_like_input(self):
        evidence = """
Control | What It Does | How to Deploy | Status
SSO/SAML/SCIM | Ties access to corporate identity | Standard IdP integration | In Progress
Cowork in audit logs/Compliance API | Not available any tier | N/A | Deferred
""".strip()
        result = generate_assessment("Claude CoWork", "saas", evidence)

        self.assertEqual(result["vendor"]["name"], "Claude CoWork")
        self.assertGreaterEqual(len(result["controls"]), 2)
        self.assertGreaterEqual(len(result["risks"]), 3)
        self.assertEqual(result["controls"][1]["status"], "Deferred")


if __name__ == "__main__":
    unittest.main()
