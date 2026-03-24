import unittest
import xml.etree.ElementTree as ET

from generate_risk_ticket import generate_ticket, validate_vendor_name


class TestGenerateRiskTicket(unittest.TestCase):
    def test_generates_ticket_for_known_type(self):
        output = generate_ticket("Acme Vendor", "saas")
        self.assertIn("<vendor_service_description>", output)
        self.assertIn("- Severity: HIGH", output)
        self.assertIn("<comments_section>", output)

    def test_vendor_name_xml_escaped(self):
        output = generate_ticket("Acme & Co", "analytics")
        self.assertIn("Acme &amp; Co", output)

    def test_rejects_vendor_name_with_disallowed_characters(self):
        with self.assertRaises(ValueError):
            validate_vendor_name("Bad<xml>")

    def test_output_is_well_formed_xml_with_single_root(self):
        output = generate_ticket("Acme Vendor", "payments")
        root = ET.fromstring(output)
        self.assertEqual(root.tag, "risk_management_ticket")
        self.assertIsNotNone(root.find("vendor_service_description"))
        self.assertIsNotNone(root.find("security_risks"))


if __name__ == "__main__":
    unittest.main()
