import unittest
from unittest.mock import patch

from core.config import parse_args
from core.runtime.entities import PageInventory, PageRecord
from core.runtime.scan_context import ScanContext
from plugins.csp_strength import CSPStrengthPlugin
from plugins.info_headers import InfoHeadersPlugin
from plugins.mixed_content import MixedContentPlugin
from plugins.url_secrets import UrlSecretsPlugin


class FakeDriver:
    def __init__(self, resources):
        self._resources = resources

    def execute_script(self, _script, *_args):
        return self._resources


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


class FakeClient:
    def __init__(self, headers):
        self._response = FakeResponse(headers)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, _url):
        return self._response


def _context():
    settings = parse_args(["--target", "https://target.test"])
    return ScanContext(settings)


def _page(url):
    return PageRecord(url=url, path=url, source="test")


def _codes(result):
    return {finding.title.split(": ", 1)[-1] for finding in result.findings}


class MixedContentTests(unittest.TestCase):
    def test_supports_only_https_pages(self):
        plugin = MixedContentPlugin(_context(), None, None, None)
        self.assertTrue(plugin.supports(PageInventory("https://t.test", "", "")))
        self.assertFalse(plugin.supports(PageInventory("http://t.test", "", "")))

    def test_flags_active_and_passive_http_resources(self):
        context = _context()
        context.driver = FakeDriver(
            [
                {"tag": "script", "url": "http://cdn.test/a.js"},
                {"tag": "img", "url": "http://cdn.test/logo.png"},
                {"tag": "link", "url": "https://ok.test/site.css"},
            ]
        )
        plugin = MixedContentPlugin(context, None, None, None)
        inventory = PageInventory("https://target.test/page", "", "")
        result = plugin.scan(_page("https://target.test/page"), inventory)

        by_severity = {finding.severity for finding in result.findings}
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(by_severity, {"HIGH", "LOW"})
        # The HTTPS stylesheet is not mixed content and must not be flagged.
        joined = str([finding.evidence for finding in result.findings])
        self.assertNotIn("ok.test", joined)


class InfoHeadersTests(unittest.TestCase):
    def test_flags_version_disclosing_headers(self):
        context = _context()
        context.driver = object()
        plugin = InfoHeadersPlugin(context, None, None, None)
        headers = {
            "Server": "Apache/2.4.29 (Ubuntu)",
            "X-Powered-By": "PHP/7.2.24",
            "X-Frame-Options": "DENY",
        }
        with patch(
            "plugins.info_headers.client_from_driver",
            lambda *a, **k: FakeClient(headers),
        ):
            result = plugin.scan(_page("https://target.test/"), None)

        names = {finding.evidence["header"] for finding in result.findings}
        self.assertEqual(names, {"Server", "X-Powered-By"})
        self.assertTrue(
            all(finding.severity == "LOW" for finding in result.findings)
        )

    def test_same_origin_is_reported_once(self):
        context = _context()
        context.driver = object()
        plugin = InfoHeadersPlugin(context, None, None, None)
        headers = {"Server": "nginx/1.18.0"}
        with patch(
            "plugins.info_headers.client_from_driver",
            lambda *a, **k: FakeClient(headers),
        ):
            first = plugin.scan(_page("https://target.test/a"), None)
            second = plugin.scan(_page("https://target.test/b"), None)
        self.assertEqual(len(first.findings), 1)
        self.assertEqual(second.findings, [])


class CSPStrengthTests(unittest.TestCase):
    def _scan(self, csp):
        context = _context()
        context.driver = object()
        plugin = CSPStrengthPlugin(context, None, None, None)
        headers = {"Content-Security-Policy": csp} if csp else {}
        with patch(
            "plugins.csp_strength.client_from_driver",
            lambda *a, **k: FakeClient(headers),
        ):
            return plugin.scan(_page("https://target.test/"), None)

    def test_weak_policy_is_flagged(self):
        result = self._scan("default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.assertEqual(
            _codes(result),
            {"unsafe-inline", "missing-frame-ancestors", "missing-base-uri"},
        )

    def test_strong_policy_has_no_findings(self):
        result = self._scan(
            "default-src 'none'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'"
        )
        self.assertEqual(result.findings, [])

    def test_absent_policy_is_ignored(self):
        result = self._scan(None)
        self.assertEqual(result.findings, [])


class UrlSecretsTests(unittest.TestCase):
    def test_flags_sensitive_params_in_page_and_links(self):
        plugin = UrlSecretsPlugin(_context(), None, None, None)
        inventory = PageInventory(
            url="https://target.test/reset",
            title="",
            body_text="",
            links=[
                "https://target.test/p?sessionid=XYZ&x=2",
                "https://target.test/ok?ref=3",
                "https://target.test/z?monkey=1",
            ],
        )
        result = plugin.scan(
            _page("https://target.test/reset?token=abc123&ref=1"),
            inventory,
        )
        params = {finding.evidence["parameter"] for finding in result.findings}
        self.assertEqual(params, {"token", "sessionid"})
        joined = str([finding.evidence["url"] for finding in result.findings])
        self.assertNotIn("abc123", joined)
        self.assertNotIn("XYZ", joined)


if __name__ == "__main__":
    unittest.main()
