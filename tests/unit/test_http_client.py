import unittest
from unittest.mock import patch

import httpx

from core.config import parse_args
from core.net import (
    browser_cookies,
    build_client,
    client_from_driver,
)


class _FakeDriver:
    def __init__(self, cookies):
        self._cookies = cookies

    def get_cookies(self):
        return self._cookies


class HttpClientTests(unittest.TestCase):
    def setUp(self):
        self.settings = parse_args(["--target", "https://target.test"])

    def test_build_client_follows_redirects_and_sets_user_agent(self):
        with build_client(self.settings) as client:
            self.assertIsInstance(client, httpx.Client)
            self.assertTrue(client.follow_redirects)
            self.assertEqual(
                client.headers.get("user-agent"), "banon-web-scanner"
            )

    def test_build_client_can_disable_redirects(self):
        with build_client(self.settings, follow_redirects=False) as client:
            self.assertFalse(client.follow_redirects)

    def test_http2_downgrades_gracefully_when_h2_missing(self):
        # Config requests HTTP/2; a missing h2 extra must not raise.
        with patch(
            "core.net.http_client.http2_available", return_value=False
        ):
            with build_client(self.settings) as client:
                self.assertIsInstance(client, httpx.Client)

    def test_client_from_driver_seeds_browser_cookies(self):
        driver = _FakeDriver([{"name": "session", "value": "abc"}])
        with client_from_driver(driver, self.settings) as client:
            self.assertEqual(client.cookies.get("session"), "abc")

    def test_browser_cookies_skips_unnamed_cookies(self):
        driver = _FakeDriver(
            [{"name": "a", "value": "1"}, {"value": "no-name"}]
        )
        self.assertEqual(browser_cookies(driver), {"a": "1"})


if __name__ == "__main__":
    unittest.main()
