import unittest
from unittest.mock import patch

from backend.research import _fetch, gather_vendor_evidence


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

    @patch('backend.research._is_safe_url')
    @patch('backend.research.urllib.request.build_opener')
    def test_fetch_revalidates_final_redirect_target(self, mock_build_opener, mock_is_safe_url):
        mock_is_safe_url.side_effect = [True, False]  # initial URL safe, final redirected URL unsafe

        class FakeResp:
            headers = {'Content-Type': 'text/html'}

            def geturl(self):
                return 'http://169.254.169.254/latest/meta-data'

            def read(self, *_):
                return b'<html>secret</html>'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, req, timeout=8):
                return FakeResp()

        mock_build_opener.return_value = FakeOpener()

        self.assertEqual(_fetch('https://example.com/start'), '')


if __name__ == '__main__':
    unittest.main()
