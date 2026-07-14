import unittest
from unittest.mock import Mock, patch

from core.config import parse_args
from core.discovery.crawler import DiscoveryEngine
from core.runtime.entities import ControlTarget, PageInventory, PageRecord
from core.runtime.scan_context import ScanContext
from core.runtime.scan_engine import ScanEngine
from core.workflows.workflow_engine import WorkflowEngine


class FakeActions:
    def __init__(self, inspector):
        self.inspector = inspector
        self.clicked = False

    def navigate(self, _url):
        self.inspector.clicked = False

    def click(self, _control):
        self.clicked = True
        self.inspector.clicked = True


class FakeInspector:
    def __init__(self, before, after):
        self.before = before
        self.after = after
        self.clicked = False

    def inspect_current(self):
        return self.after if self.clicked else self.before


class FakeDetector:
    @staticmethod
    def fingerprint(inventory):
        return f"{inventory.url}|{inventory.body_text}"

    @staticmethod
    def is_registration_form(_form, _inventory):
        return False

    @staticmethod
    def is_login_form(_form, _inventory):
        return False


class FakeBrowser:
    def __init__(self, after):
        self.after = after

    def inspect(self):
        return self.after


class FakeWait:
    def __init__(self):
        self.stabilized = 0

    def dom_stable(self):
        self.stabilized += 1


class PanelActions:
    """Model a control that opens a panel in place instead of navigating."""

    def __init__(self, inspector, opener_id):
        self.inspector = inspector
        self.opener_id = opener_id
        self.wait = FakeWait()
        self.clicks: list[str] = []

    def navigate(self, _url):
        self.inspector.state = "base"

    def click(self, control):
        self.clicks.append(control.element_id)
        if control.element_id == self.opener_id:
            self.inspector.state = "panel"


class PanelInspector:
    def __init__(self, base, panel):
        self.base = base
        self.panel = panel
        self.state = "base"

    def inspect_current(self):
        return self.panel if self.state == "panel" else self.base


class WorkflowDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.settings = parse_args(["--target", "https://target.test"])

    def test_standalone_navigation_button_discovers_destination(self):
        button = ControlTarget(
            element_id="nav",
            frame_path=(),
            tag="button",
            control_type="submit",
            text="Open dashboard",
        )
        before = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[button],
        )
        after = PageInventory(
            url="https://target.test/dashboard",
            title="Dashboard",
            body_text="Dashboard",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            self.settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertTrue(actions.clicked)
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/dashboard"],
        )

    def test_visible_link_discovers_destination_without_route_terms(self):
        link = ControlTarget(
            element_id="register",
            frame_path=(),
            tag="a",
            control_type="a",
            text="Register",
            attributes={"href": "https://target.test/register"},
        )
        before = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[link],
        )
        after = PageInventory(
            url="https://target.test/register",
            title="Register",
            body_text="Create account",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            self.settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertTrue(actions.clicked)
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/register"],
        )

    def test_destructive_standalone_button_is_not_clicked(self):
        button = ControlTarget(
            element_id="delete",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Delete account",
        )
        before = PageInventory(
            url="https://target.test",
            title="Settings",
            body_text="Settings",
            controls=[button],
        )
        after = PageInventory(
            url="https://target.test/deleted",
            title="Deleted",
            body_text="Deleted",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            self.settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertFalse(actions.clicked)
        self.assertEqual(discovered, [])

    def test_allow_destructive_flag_permits_blocked_control(self):
        settings = parse_args(
            [
                "--target",
                "https://target.test",
                "--allow-destructive",
            ]
        )
        button = ControlTarget(
            element_id="delete",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Delete account",
        )
        before = PageInventory(
            url="https://target.test",
            title="Settings",
            body_text="Settings",
            controls=[button],
        )
        after = PageInventory(
            url="https://target.test/deleted",
            title="Deleted",
            body_text="Deleted",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertTrue(actions.clicked)
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/deleted"],
        )

    def test_allow_specific_destructive_term_permits_only_that(self):
        settings = parse_args(
            [
                "--target",
                "https://target.test",
                "--allow-destructive",
                "delete",
            ]
        )
        delete_button = ControlTarget(
            element_id="delete",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Delete account",
        )
        transfer_button = ControlTarget(
            element_id="transfer",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Transfer funds",
        )
        before = PageInventory(
            url="https://target.test",
            title="Settings",
            body_text="Settings",
            controls=[delete_button, transfer_button],
        )
        after = PageInventory(
            url="https://target.test/deleted",
            title="Deleted",
            body_text="Deleted",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)
        engine = WorkflowEngine(actions, inspector, FakeDetector(), settings)

        candidate_ids = [
            control.element_id
            for control in engine._navigation_candidates(before)
        ]
        self.assertIn("delete", candidate_ids)
        self.assertNotIn("transfer", candidate_ids)

        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/deleted"],
        )

    def test_unknown_destructive_term_is_rejected(self):
        with self.assertRaises(SystemExit):
            parse_args(
                [
                    "--target",
                    "https://target.test",
                    "--allow-destructive",
                    "frobnicate",
                ]
            )

    def test_external_link_is_not_clicked(self):
        link = ControlTarget(
            element_id="admin",
            frame_path=(),
            tag="a",
            control_type="a",
            text="Admin",
            attributes={"href": "https://admin.target.test/users"},
        )
        before = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[link],
        )
        after = PageInventory(
            url="https://admin.target.test/users",
            title="Admin",
            body_text="Admin",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            self.settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertFalse(actions.clicked)
        self.assertEqual(discovered, [])

    def test_form_submit_button_is_not_clicked_as_navigation(self):
        button = ControlTarget(
            element_id="submit",
            frame_path=(),
            tag="button",
            control_type="submit",
            text="Open dashboard",
            form_id="form",
        )
        before = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[button],
        )
        after = PageInventory(
            url="https://target.test/dashboard",
            title="Dashboard",
            body_text="Dashboard",
        )
        inspector = FakeInspector(before, after)
        actions = FakeActions(inspector)

        engine = WorkflowEngine(
            actions,
            inspector,
            FakeDetector(),
            self.settings,
        )
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            before,
        )

        self.assertFalse(actions.clicked)
        self.assertEqual(discovered, [])

    def test_dynamic_panel_reveals_route_without_url_change(self):
        menu = ControlTarget(
            element_id="menu",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Menu",
        )
        dashboard = ControlTarget(
            element_id="dash",
            frame_path=(),
            tag="a",
            control_type="a",
            text="Dashboard",
            attributes={"href": "https://target.test/dashboard"},
        )
        base = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[menu],
        )
        panel = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home menu open",
            controls=[menu, dashboard],
        )
        inspector = PanelInspector(base, panel)
        actions = PanelActions(inspector, opener_id="menu")

        engine = WorkflowEngine(actions, inspector, FakeDetector(), self.settings)
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            base,
        )

        self.assertEqual(actions.clicks, ["menu"])
        self.assertGreaterEqual(actions.wait.stabilized, 1)
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/dashboard"],
        )
        self.assertEqual(discovered[0].source, "workflow_panel")
        # The panel's newly visible control is folded into the page inventory.
        self.assertIn("dash", [control.element_id for control in base.controls])

    def test_dynamic_panels_disabled_by_config_reveals_nothing(self):
        settings = parse_args(["--target", "https://target.test"])
        settings.defaults["workflows"]["explore_dynamic_panels"] = False
        menu = ControlTarget(
            element_id="menu",
            frame_path=(),
            tag="button",
            control_type="button",
            text="Menu",
        )
        dashboard = ControlTarget(
            element_id="dash",
            frame_path=(),
            tag="a",
            control_type="a",
            text="Dashboard",
            attributes={"href": "https://target.test/dashboard"},
        )
        base = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home",
            controls=[menu],
        )
        panel = PageInventory(
            url="https://target.test",
            title="Home",
            body_text="Home menu open",
            controls=[menu, dashboard],
        )
        inspector = PanelInspector(base, panel)
        actions = PanelActions(inspector, opener_id="menu")

        engine = WorkflowEngine(actions, inspector, FakeDetector(), settings)
        discovered = engine.safe_transition_pages(
            PageRecord("https://target.test", "/", "test"),
            base,
        )

        self.assertEqual(discovered, [])

    def test_login_transition_queues_browser_landing_page(self):
        settings = parse_args(
            [
                "--target",
                "https://target.test",
                "--username",
                "user1",
                "--password",
                "password1",
            ]
        )
        context = ScanContext(settings)
        engine = ScanEngine(context)
        engine.browser = FakeBrowser(
            PageInventory(
                url="https://target.test/dashboard",
                title="Dashboard",
                body_text="Dashboard",
            )
        )
        engine.detector = FakeDetector()
        engine.discovery = DiscoveryEngine(settings.target, settings)
        engine.workflows = Mock()
        engine._navigation_discoveries = Mock(return_value=[])

        fake_auth = Mock()
        fake_auth.login_form.return_value = object()
        fake_auth.login.return_value = True

        with patch(
            "core.runtime.scan_engine.Authenticator",
            return_value=fake_auth,
        ):
            discovered = engine._authentication_discoveries(
                PageRecord(
                    "https://target.test/login",
                    "/login",
                    "test",
                ),
                PageInventory(
                    url="https://target.test/login",
                    title="Login",
                    body_text="Login",
                ),
                status="pending",
                queue_for_scan=True,
            )

        self.assertTrue(context.authenticated)
        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/dashboard"],
        )
        self.assertEqual(discovered[0].source, "authentication")
        self.assertEqual(discovered[0].status, "pending")

    def test_known_pages_are_not_announced_as_new_discoveries(self):
        settings = parse_args(["--target", "https://target.test"])
        context = ScanContext(settings)
        context.add_page(
            PageRecord(
                "https://target.test/register",
                "/register",
                "existing",
            )
        )
        engine = ScanEngine(context)
        engine.discovery = DiscoveryEngine(settings.target, settings)
        engine.discovery.probe_pages = Mock(
            side_effect=lambda pages, progress=None: pages
        )
        engine.workflows = Mock()
        engine.workflows.safe_transition_pages.return_value = [
            PageRecord(
                "https://target.test/register",
                "/register",
                "workflow",
            ),
            PageRecord(
                "https://target.test/login",
                "/login",
                "workflow",
            ),
        ]

        discovered = engine._navigation_discoveries(
            PageRecord("https://target.test", "/", "test"),
            PageInventory(
                url="https://target.test",
                title="Home",
                body_text="Home",
            ),
            status="pending",
        )

        self.assertEqual(
            [page.url for page in discovered],
            ["https://target.test/login"],
        )
        probed_pages = engine.discovery.probe_pages.call_args.args[0]
        self.assertEqual(
            [page.url for page in probed_pages],
            ["https://target.test/login"],
        )


if __name__ == "__main__":
    unittest.main()
