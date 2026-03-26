import unittest

from backend.engine import _infer_risks_from_controls, generate_assessment, normalize_status


class TestBackendEngine(unittest.TestCase):
    def test_normalize_status(self):
        self.assertEqual(normalize_status("In Progress"), "In Progress")
        self.assertEqual(normalize_status("deferred"), "Deferred")
        self.assertEqual(normalize_status("unknown"), "In Progress")

    def test_generate_assessment_from_table_like_input(self):
        evidence = """
Control | What It Does | How to Deploy | Status
SSO/SAML/SCIM | Ties access to corporate identity | Standard IdP integration | In Progress
        Audit logs/Compliance API | Not available any tier | N/A | Deferred
""".strip()
        result = generate_assessment("ExampleVendor", "saas", evidence)

        self.assertEqual(result["vendor"]["name"], "ExampleVendor")
        self.assertGreaterEqual(len(result["controls"]), 2)
        self.assertGreaterEqual(len(result["risks"]), 3)
        self.assertEqual(result["controls"][1]["status"], "Deferred")

    def test_infer_risks_does_not_mutate_global_defaults(self):
        escalated = _infer_risks_from_controls(
            [{"control_name": "audit logging", "status_rationale": "", "notes": ""}]
        )
        self.assertEqual(escalated[1]["severity"], "CRITICAL")

        baseline = _infer_risks_from_controls(
            [{"control_name": "SSO/SAML/SCIM", "status_rationale": "", "notes": ""}]
        )
        self.assertEqual(baseline[1]["severity"], "HIGH")

    def test_vendor_profiles_generate_distinct_risk_sets(self):
        claude = generate_assessment("Claude CoWork", "saas", "")
        vertex = generate_assessment("Vertex", "saas", "")

        self.assertNotEqual(
            [risk["title"] for risk in claude["risks"]],
            [risk["title"] for risk in vertex["risks"]],
        )
        self.assertIn("unattended", claude["risks"][0]["title"].lower())
        self.assertIn("model", vertex["risks"][0]["title"].lower())


if __name__ == "__main__":
    unittest.main()
