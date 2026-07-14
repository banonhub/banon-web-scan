import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core.browser.driver_factory import create_driver
from core.browser.page_inspector import PageInspector
from core.config import parse_args
from core.runtime.entities import PageRecord
from core.runtime.scan_context import ScanContext
from core.runtime.scan_engine import ScanEngine


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/app"):
            body = """
            <!doctype html><title>Application</title>
            <button onclick="location.href='/'">Go home</button>
            <div role="textbox" aria-label="Query"></div>
            """
        elif self.path.startswith("/search"):
            body = (
                "<!doctype html><title>Search</title>"
                "<p>Records: alpha beta gamma delta epsilon</p>"
            )
        else:
            body = """
            <!doctype html><title>Home</title>
            <button onclick="location.href='/app'">Open application</button>
            <a href="/search">Search records</a>
            """
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request, _client_address):
        return


class DiscoveryFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = (
                "<title>Application</title>"
                "<p>This is a demo application.</p>"
                '<button onclick="location.href=\'/login\'">Login</button>'
                '<a href="/register">Register</a>'
                '<button onclick="location.href=\'/missing\'">Open missing</button>'
            )
        elif self.path == "/login":
            body = (
                "<title>Login</title>"
                '<form action="/session" method="post">'
                '<label for="identity">Identity</label>'
                '<input id="identity" name="identity">'
                '<label for="secret">Secret</label>'
                '<input id="secret" type="password">'
                "</form>"
            )
        elif self.path == "/register":
            body = (
                "<title>Register</title>"
                '<form action="/users" method="post">'
                '<label for="identity">Identity</label>'
                '<input id="identity" name="identity">'
                '<label for="secret">Secret</label>'
                '<input id="secret" type="password">'
                '<label for="confirm">Confirm password</label>'
                '<input id="confirm" type="password">'
                "</form>"
            )
        else:
            self.send_response(404)
            self.end_headers()
            return
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


@unittest.skipUnless(
    os.environ.get("BANON_BROWSER_TESTS") == "1",
    "Set BANON_BROWSER_TESTS=1 to run Chrome integration tests",
)
class BrowserInventoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = parse_args([])
        cls.settings.headless = True
        cls.driver = create_driver(cls.settings)

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()

    def test_frames_shadow_dom_and_semantic_controls_are_inventoried(self):
        fixture = (
            Path(__file__).resolve().parents[1]
            / "fixtures"
            / "complex_page.html"
        )
        inventory = PageInspector(
            self.driver,
            self.settings,
        ).inspect_url(fixture.as_uri())
        labels = {control.label for control in inventory.controls}
        self.assertIn("Account identity", labels)
        self.assertIn("Framed search", labels)
        self.assertIn("Shadow query", labels)
        self.assertGreaterEqual(inventory.frame_count, 1)
        self.assertGreaterEqual(inventory.shadow_root_count, 1)

    def test_selected_page_analysis_recursively_expands_and_restores(self):
        server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            settings = parse_args(["--target", target, "--headless"])
            context = ScanContext(settings)
            context.attach_driver(self.driver)
            engine = ScanEngine(context)

            engine.analyze_page(PageRecord(target, "/", "selected"))

            self.assertIn(f"{target}/app", context.pages)
            self.assertIn(f"{target}/search", context.pages)
            self.assertEqual(self.driver.current_url.rstrip("/"), target)
        finally:
            server.shutdown()
            server.server_close()

    def test_autonomous_run_discovers_pages_without_plugins(self):
        server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            settings = parse_args(["--target", target, "--headless"])
            settings.defaults["discovery"]["maximum_pages"] = 5
            context = ScanContext(settings)
            context.attach_driver(self.driver)
            engine = ScanEngine(context)
            self.assertTrue(engine.target_reachable())
            result = engine.run()
            self.assertTrue(result["success"])
            self.assertGreaterEqual(result["pages_discovered"], 2)
            self.assertGreaterEqual(result["pages_scanned"], 2)
            self.assertIsInstance(result["findings"], list)
        finally:
            server.shutdown()
            server.server_close()

    def test_discovery_only_filters_missing_button_destinations(self):
        server = FixtureServer(("127.0.0.1", 0), DiscoveryFixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            settings = parse_args(["--target", target, "--headless"])
            context = ScanContext(settings)
            context.attach_driver(self.driver)
            pages = ScanEngine(context).discover_only()
            self.assertEqual(
                {page.path for page in pages},
                {"/", "/login", "/register"},
            )
            self.assertFalse(context.findings)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
