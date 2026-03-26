import unittest
from unittest.mock import patch

from backend.research import gather_vendor_evidence


class TestResearch(unittest.TestCase):
    @patch('backend.research._fetch')
    @patch('backend.research._search_duckduckgo')
    def test_gather_vendor_evidence_collects_sources(self, mock_search, mock_fetch):
        mock_search.return_value = [
            type('S', (), {'title': 'Vendor Docs', 'url': 'https://example.com/docs', 'snippet': ''})(),
        ]
        mock_fetch.return_value = '<html><body><h1>Security</h1><p>SOC 2 Type II</p></body></html>'

        evidence, sources = gather_vendor_evidence('ExampleVendor', max_sources=1)

        self.assertIn('SOURCE: Vendor Docs | https://example.com/docs', evidence)
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]['url'], 'https://example.com/docs')


if __name__ == '__main__':
    unittest.main()
