import unittest
from unittest.mock import Mock, patch

import httpx

from core.config import parse_args
from core.discovery.crawler import DiscoveryEngine
from core.discovery.scope_policy import ScopePolicy
from core.runtime.entities import PageRecord
from core.runtime.scan_context import ScanContext
from core.workflows.authenticator import Authenticator


class ContextAndScopeTests(unittest.TestCase):
    def setUp(self):
        self.settings = parse_args(["--target", "https://target.test"])

    def test_scope_rejects_external_origin(self):
        policy = ScopePolicy("https://target.test", self.settings)
        self.assertIsNone(policy.normalize("https://external.test/path"))

    def test_scope_rejects_related_admin_subdomain_by_default(self):
        policy = ScopePolicy("https://target.test", self.settings)
        self.assertIsNone(
            policy.normalize("https://admin.target.test/users")
        )
        self.assertIsNone(
            policy.normalize("https://untrusted.target.test/users")
        )

    def test_initial_discovery_starts_with_target_only(self):
        discovery = DiscoveryEngine(
            "https://target.test",
            self.settings,
        )
        urls = {page.url for page in discovery.initial_pages()}
        self.assertEqual(urls, {"https://target.test"})

    def test_concurrent_probes_preserve_order_and_isolate_failures(self):
        discovery = DiscoveryEngine(
            "https://target.test",
            self.settings,
        )
        pages = [
            PageRecord(
                f"https://target.test/{name}",
                f"/{name}",
                "test",
            )
            for name in ("first", "missing", "third")
        ]
        progress = []

        def response_for(url, **_kwargs):
            if url.endswith("/missing"):
                raise httpx.ConnectError("offline")
            response = Mock()
            response.status_code = 200
            response.url = url
            return response

        fake_client = Mock()
        fake_client.get.side_effect = response_for
        fake_client.close.return_value = None

        with patch(
            "core.discovery.crawler.build_client",
            return_value=fake_client,
        ):
            results = discovery.probe_pages(
                pages,
                progress=lambda *event: progress.append(event),
            )

        self.assertEqual(
            [page.path for page in results],
            ["/first", "/third"],
        )
        self.assertEqual(len(progress), 3)
        self.assertTrue(
            any(
                event[0].path == "/missing" and not event[1]
                for event in progress
            )
        )

    def test_scope_normalizes_query_and_keeps_spa_fragment(self):
        policy = ScopePolicy("https://target.test", self.settings)
        self.assertEqual(
            policy.normalize("https://target.test/app?b=2&a=1#/account"),
            "https://target.test/app?a=1&b=2#/account",
        )

    def test_scope_avoids_logout_routes_from_configuration(self):
        policy = ScopePolicy("https://target.test", self.settings)
        self.assertIsNone(policy.normalize("https://target.test/logout"))

    def test_root_normalizes_to_bare_origin_without_duplicate(self):
        policy = ScopePolicy("https://target.test", self.settings)
        # Both the slashed and unslashed root collapse to the same key, so the
        # root is never queued twice.
        self.assertEqual(
            policy.normalize("https://target.test/"),
            "https://target.test",
        )
        self.assertEqual(
            policy.normalize("https://target.test"),
            "https://target.test",
        )

    def test_authenticated_page_requeues_public_page(self):
        context = ScanContext(self.settings)
        context.add_page(
            PageRecord(
                url="https://target.test/private",
                path="/private",
                source="public",
            )
        )
        context.pages["https://target.test/private"].status = "complete"
        replaced = context.add_page(
            PageRecord(
                url="https://target.test/private",
                path="/private",
                source="authenticated",
                authenticated=True,
            )
        )
        self.assertTrue(replaced)
        self.assertEqual(
            context.pages["https://target.test/private"].status,
            "pending",
        )

    def test_authentication_clears_plugin_page_cache(self):
        context = ScanContext(self.settings)
        context.completed_plugin_pages.add(("plugin", "/page", False))
        context.mark_authenticated({"url": "/account"})
        self.assertTrue(context.authenticated)
        self.assertFalse(context.completed_plugin_pages)

    def test_authentication_promotes_previously_discovered_routes(self):
        context = ScanContext(self.settings)
        context.add_page(
            PageRecord(
                url="https://target.test/profile/bio",
                path="/profile/bio",
                source="public",
                status="discovered",
            )
        )
        context.promote_pages_to_authenticated(queue_for_scan=False)
        page = context.pages["https://target.test/profile/bio"]
        self.assertTrue(page.authenticated)
        self.assertEqual(page.status, "discovered")

        page.authenticated = False
        context.promote_pages_to_authenticated(queue_for_scan=True)
        self.assertEqual(page.status, "pending")

    def test_authenticated_route_candidates_exclude_public_pages(self):
        context = ScanContext(self.settings)
        context.add_page(
            PageRecord(
                url="https://target.test",
                path="/",
                source="initial",
                authenticated=True,
            )
        )
        context.add_page(
            PageRecord(
                url="https://target.test/register",
                path="/register",
                source="workflow",
                authenticated=True,
            )
        )
        context.add_page(
            PageRecord(
                url="https://target.test/dashboard",
                path="/dashboard",
                source="authentication",
                authenticated=True,
            )
        )
        context.add_page(
            PageRecord(
                url="https://target.test/tools",
                path="/tools",
                source="authenticated_workflow",
                authenticated=True,
            )
        )

        auth = Authenticator(context, browser=None, detector=None)

        self.assertEqual(
            [page.path for page in auth.authenticated_route_candidates()],
            ["/dashboard", "/tools"],
        )


if __name__ == "__main__":
    unittest.main()
