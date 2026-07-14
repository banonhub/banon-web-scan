from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

from core.browser.base_page import BasePage
from core.net import build_client, request_error
from core.config.list_provider import ListProvider
from core.discovery.crawler import DiscoveryEngine
from core.plugins.plugin_manager import PluginManager
from core.runtime.entities import (
    Barrier,
    PageAnalysis,
    PageInventory,
    PageRecord,
    PluginSuggestion,
)
from core.runtime.scan_context import ScanContext
from core.workflows import Authenticator
from core.workflows.state_detector import StateDetector
from core.workflows.workflow_engine import WorkflowEngine


ProgressHandler = Callable[[str, dict], None]
BarrierHandler = Callable[[Barrier], bool]


class ScanEngine:
    """Discovery and page-scanning engine backed by one preserved browser."""

    def __init__(
        self,
        context: ScanContext,
        *,
        progress: ProgressHandler | None = None,
        barrier_handler: BarrierHandler | None = None,
    ):
        if not context.target:
            raise ValueError("The scan context has no target")
        self.context = context
        self.settings = context.settings
        self.progress = progress or (lambda _event, _data: None)
        self.barrier_handler = barrier_handler
        self.lists = ListProvider(self.settings)
        self.manager = PluginManager(self.settings)
        self.browser: BasePage | None = None
        self.detector: StateDetector | None = None
        self.discovery: DiscoveryEngine | None = None
        self.workflows: WorkflowEngine | None = None
        self.plugin_classes = []
        self.plugins_announced = False

    def target_reachable(self) -> bool:
        application = self.settings.get("application")
        timeout = float(application["reachability_timeout"])
        target = self.context.target.rstrip("/")
        candidates = [target]
        candidates.extend(
            f"{target}/{path.lstrip('/')}"
            for path in application["reachability_paths"]
        )
        with build_client(
            self.settings,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            for url in dict.fromkeys(candidates):
                try:
                    response = client.get(url)
                except request_error:
                    continue
                if response.status_code in application[
                    "reachable_status_codes"
                ]:
                    return True
        return False

    def discover_only(self) -> list[PageRecord]:
        """Discover and classify reachable pages without running plugins.

        Additive: routes already found (for example by the route-discovery
        plugin clicking buttons) are preserved and merged with the crawl
        results instead of being cleared first."""
        self._prepare()
        limits = self.settings.get("discovery")
        maximum_pages = int(limits["maximum_pages"])
        maximum_depth = int(limits["maximum_depth"])
        queue = self.discovery.probe_pages(
            self.discovery.initial_pages(),
            progress=self._probe_progress,
        )
        visited: set[str] = set()

        while queue and len(visited) < maximum_pages:
            page = queue.pop(0)
            if page.url in visited or page.depth > maximum_depth:
                continue
            visited.add(page.url)
            self.progress("discovery_page", {"page": page})
            try:
                inventory = self.browser.open(page.url)
            except Exception as exc:
                self.context.record_barriers(
                    [Barrier("navigation", page.url, str(exc))]
                )
                continue

            page.final_url = inventory.url
            page.title = inventory.title
            page.page_type = self._classify(inventory)
            page.status = "discovered"
            self.context.add_page(page)
            self.context.record_barriers(self.browser.inspector.barriers)

            candidates = self._navigation_discoveries(
                page,
                inventory,
                status="discovered",
            )
            candidates.extend(
                self._authentication_discoveries(
                    page,
                    inventory,
                    status="discovered",
                    queue_for_scan=False,
                )
            )
            unvisited = [
                candidate
                for candidate in candidates
                if candidate.url not in visited
                and candidate.url not in self.context.pages
            ]
            queue.extend(unvisited)

        return list(self.context.pages.values())

    def scan_page(
        self,
        page: PageRecord,
        *,
        force: bool = False,
        queue_discovered: bool = False,
        plugin_names: set[str] | None = None,
    ) -> dict:
        """Run compatible plugins against one user-selected page."""
        self._prepare()
        finding_start = len(self.context.findings)
        barrier_start = len(self.context.barriers)
        pages_before = set(self.context.pages)
        self.progress("page", {"page": page})

        try:
            inventory = self.browser.open(page.url)
        except Exception as exc:
            barrier = Barrier("navigation", page.url, str(exc))
            self.context.record_barriers([barrier])
            return self._page_result(
                page,
                finding_start,
                barrier_start,
                pages_before,
            )

        page.final_url = inventory.url
        page.title = inventory.title
        page.page_type = self._classify(inventory)
        self.context.current_page = page
        self.context.current_inventory = inventory
        self.context.record_barriers(self.browser.inspector.barriers)
        inventory = self._handle_captcha(page, inventory)
        if inventory is None:
            return self._page_result(
                page,
                finding_start,
                barrier_start,
                pages_before,
            )

        authenticated_during_page = False

        for plugin_class in self.plugin_classes:
            if plugin_names is not None and plugin_class.NAME not in plugin_names:
                continue
            key = (
                plugin_class.NAME,
                page.url,
                self.context.authenticated,
            )
            if not force and key in self.context.completed_plugin_pages:
                continue
            plugin = plugin_class(
                self.context,
                self.browser,
                self.lists,
                self.detector,
            )
            if not plugin.supports(inventory):
                self.context.completed_plugin_pages.add(key)
                continue

            self.progress("plugin", {"name": plugin.NAME, "page": page})
            self._watch_note(f"Check: {plugin.NAME}", plugin.DESCRIPTION)
            try:
                result = plugin.scan(page, inventory)
            except Exception as exc:
                self.context.record_barriers(
                    [
                        Barrier(
                            "plugin_error",
                            page.url,
                            f"{plugin.NAME}: {exc}",
                        )
                    ]
                )
                self.context.completed_plugin_pages.add(key)
                continue

            was_authenticated = self.context.authenticated
            self.context.record_findings(result.findings)
            self.context.record_barriers(result.barriers)
            if result.authenticated and not was_authenticated:
                self.context.mark_authenticated(
                    result.authentication_evidence
                )
                self.context.promote_pages_to_authenticated(
                    queue_for_scan=queue_discovered
                )
                authenticated_during_page = True
                authenticated_inventory = self.browser.inspect()
                self.context.current_inventory = authenticated_inventory
                self.progress(
                    "authenticated",
                    {
                        "url": authenticated_inventory.url,
                        "evidence": result.authentication_evidence,
                    },
                )
            self.context.completed_plugin_pages.add(
                (
                    plugin_class.NAME,
                    page.url,
                    self.context.authenticated,
                )
            )
            if authenticated_during_page:
                break

        if not authenticated_during_page:
            status = "pending" if queue_discovered else "discovered"
            for discovered in self._navigation_discoveries(
                page,
                inventory,
                status=status,
            ):
                self.context.add_page(discovered)
            for discovered in self._authentication_discoveries(
                page,
                inventory,
                status=status,
                queue_for_scan=queue_discovered,
            ):
                self.context.add_page(discovered)

        page.scan_count += 1
        page.status = "tested"
        return self._page_result(
            page,
            finding_start,
            barrier_start,
            pages_before,
        )

    def analyze_page(
        self,
        page: PageRecord,
        *,
        expand_discovery: bool = True,
    ) -> PageAnalysis:
        """Inspect one page and return plugins that are currently applicable."""
        self._prepare()
        barrier_start = len(self.context.barriers)
        self.progress("analyzing", {"page": page})
        try:
            inventory = self.browser.open(page.url)
        except Exception as exc:
            barrier = Barrier("navigation", page.url, str(exc))
            self.context.record_barriers([barrier])
            empty = PageInventory(page.url, page.title, "")
            return PageAnalysis(
                page=page,
                inventory=empty,
                barriers=[barrier],
            )

        page.final_url = inventory.url
        page.title = inventory.title
        page.page_type = self._classify(inventory)
        self.context.current_page = page
        self.context.current_inventory = inventory
        self.context.record_barriers(self.browser.inspector.barriers)
        inventory = self._handle_captcha(page, inventory)
        if inventory is None:
            inventory = PageInventory(
                page.final_url or page.url,
                page.title,
                "",
                captcha_detected=True,
            )
        else:
            if expand_discovery:
                for discovered in self._navigation_discoveries(
                    page,
                    inventory,
                    status="discovered",
                ):
                    self.context.add_page(discovered)

        suggestions: list[PluginSuggestion] = []
        for plugin_class in self.plugin_classes:
            plugin = plugin_class(
                self.context,
                self.browser,
                self.lists,
                self.detector,
            )
            try:
                supported = plugin.supports(inventory)
            except Exception as exc:
                self.context.record_barriers(
                    [
                        Barrier(
                            "plugin_analysis_error",
                            page.url,
                            f"{plugin.NAME}: {exc}",
                        )
                    ]
                )
                continue
            if supported:
                suggestions.append(
                    PluginSuggestion(
                        name=plugin.NAME,
                        description=plugin.DESCRIPTION,
                    )
                )

        return PageAnalysis(
            page=page,
            inventory=inventory,
            suggestions=suggestions,
            barriers=self.context.barriers[barrier_start:],
        )

    def run(self) -> dict:
        """Run the fully autonomous non-interactive workflow."""
        self._prepare()
        self._announce_plugins()
        for page in self.discovery.probe_pages(
            self.discovery.initial_pages(),
            progress=self._probe_progress,
        ):
            page.status = "pending"
            self.context.add_page(page)

        limits = self.settings.get("discovery")
        maximum_pages = int(limits["maximum_pages"])
        scanned = 0
        while scanned < maximum_pages:
            page = self.context.next_pending_page()
            if page is None:
                break
            self.scan_page(page, queue_discovered=True)
            scanned += 1
        return self.result()

    def result(self) -> dict:
        return {
            "success": True,
            "target": self.context.target,
            "authenticated": self.context.authenticated,
            "pages_discovered": len(self.context.pages),
            "pages_scanned": sum(
                1 for page in self.context.pages.values() if page.scan_count
            ),
            "total_findings": len(self.context.findings),
            "findings": [
                finding.to_dict() for finding in self.context.findings
            ],
            "pages": [
                {
                    "path": page.path,
                    "url": page.url,
                    "title": page.title,
                    "page_type": page.page_type,
                    "status": page.status,
                    "status_code": page.status_code,
                    "authenticated": page.authenticated,
                    "scanned": bool(page.scan_count),
                    "source": page.source,
                    "depth": page.depth,
                }
                for page in self.context.pages.values()
            ],
            "barriers": [
                {
                    "kind": barrier.kind,
                    "url": barrier.url,
                    "detail": barrier.detail,
                }
                for barrier in self.context.barriers
            ],
        }

    def _prepare(self) -> None:
        if self.browser is not None:
            return
        if self.context.driver is None:
            raise RuntimeError("A shared Selenium driver must be attached")
        self.browser = BasePage(self.context.driver, self.settings)
        self.detector = StateDetector(self.context.driver, self.settings)
        self.discovery = DiscoveryEngine(
            self.context.target,
            self.settings,
        )
        self.workflows = WorkflowEngine(
            self.browser.actions,
            self.browser.inspector,
            self.detector,
            self.settings,
        )
        self.plugin_classes = self.manager.select(self.settings.scan)

    def _announce_plugins(self) -> None:
        if self.plugins_announced:
            return
        self.plugins_announced = True
        self.progress(
            "plugins",
            {"names": [plugin.NAME for plugin in self.plugin_classes]},
        )

    def _probe_progress(
        self,
        page: PageRecord,
        reachable: bool,
        status_code: int | None,
        error: str | None,
    ) -> None:
        self.progress(
            "discovery_probe",
            {
                "page": page,
                "reachable": reachable,
                "status_code": status_code,
                "error": error,
            },
        )

    def _navigation_discoveries(
        self,
        page: PageRecord,
        inventory: PageInventory,
        *,
        status: str,
    ) -> list[PageRecord]:
        discovered = self.workflows.safe_transition_pages(page, inventory)
        normalized = self._normalize_discoveries(
            page,
            discovered,
            status=status,
        )
        return self._probe_discoveries(normalized, status=status)

    def _authentication_discoveries(
        self,
        page: PageRecord,
        inventory: PageInventory,
        *,
        status: str,
        queue_for_scan: bool,
    ) -> list[PageRecord]:
        if self.context.authenticated:
            return []
        if not (self.settings.username and self.settings.password):
            return []

        auth = Authenticator(self.context, self.browser, self.detector)
        if auth.login_form(inventory) is None:
            return []
        if not auth.login(login_url=page.url):
            return []

        after_inventory = self.browser.inspect()
        evidence = {
            "url": after_inventory.url,
            "login_url": page.url,
            "source": "login_form",
        }
        self.context.mark_authenticated(evidence)
        self.context.promote_pages_to_authenticated(
            queue_for_scan=queue_for_scan
        )
        self.context.current_inventory = after_inventory
        self.progress(
            "authenticated",
            {"url": after_inventory.url, "evidence": evidence},
        )

        normalized = self.discovery.scope.normalize(after_inventory.url, page.url)
        if normalized is None:
            return []

        authenticated_page = PageRecord(
            url=normalized,
            path=self._path_for(normalized),
            source="authentication",
            authenticated=True,
            depth=page.depth + 1,
            title=after_inventory.title,
            status=status,
            final_url=after_inventory.url,
            page_type=self._classify(after_inventory),
        )
        discovered = [authenticated_page]
        discovered.extend(
            self._navigation_discoveries(
                authenticated_page,
                after_inventory,
                status=status,
            )
        )
        return self._dedupe_pages(discovered)

    def _normalize_discoveries(
        self,
        origin: PageRecord,
        discovered: list[PageRecord],
        *,
        status: str,
    ) -> list[PageRecord]:
        normalized_pages: list[PageRecord] = []
        seen: set[str] = set()
        for candidate in discovered:
            normalized = self.discovery.scope.normalize(
                candidate.url,
                origin.url,
            )
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            if normalized == origin.url:
                continue
            if normalized in self.context.pages:
                continue
            if (
                self.context.authenticated
                or origin.authenticated
                or candidate.authenticated
            ):
                candidate.authenticated = True
                if candidate.source == "workflow":
                    candidate.source = "authenticated_workflow"
                elif candidate.source == "workflow_form":
                    candidate.source = "authenticated_form"
            candidate.url = normalized
            candidate.path = self._path_for(normalized)
            candidate.status = status
            normalized_pages.append(candidate)
        return normalized_pages

    def _probe_discoveries(
        self,
        pages: list[PageRecord],
        *,
        status: str,
    ) -> list[PageRecord]:
        candidates = [
            page
            for page in pages
            if page.url not in self.context.pages
        ]
        if not candidates:
            return []
        reachable = self.discovery.probe_pages(
            candidates,
            progress=self._probe_progress,
        )
        for page in reachable:
            page.status = status
        return reachable

    @staticmethod
    def _dedupe_pages(pages: list[PageRecord]) -> list[PageRecord]:
        deduped: list[PageRecord] = []
        seen: set[str] = set()
        for page in pages:
            if page.url in seen:
                continue
            seen.add(page.url)
            deduped.append(page)
        return deduped

    def _watch_note(self, title: str, detail: str = "") -> None:
        if self.browser is None:
            return
        try:
            self.browser.actions.watch_note(title, detail)
        except Exception:
            return

    def _handle_captcha(
        self,
        page: PageRecord,
        inventory: PageInventory,
    ) -> PageInventory | None:
        if not inventory.captcha_detected:
            return inventory
        barrier = Barrier(
            "captcha",
            page.url,
            self.settings.get(
                "inspection", "captcha_barrier_message"
            ),
        )
        self.context.record_barriers([barrier])
        # Pausing for a human is opt-in: the --captcha flag enables it per run,
        # and inspection.captcha_policy can persist it in config. Either turns
        # it on; by default a detected CAPTCHA is just recorded as a coverage
        # gap and the scan continues without blocking.
        pause_enabled = (
            self.settings.captcha_pause
            or self.settings.get("inspection", "captcha_policy")
            == "pause_interactive"
        )
        if pause_enabled and self.barrier_handler:
            if self.barrier_handler(barrier):
                refreshed = self.browser.inspect()
                if not refreshed.captcha_detected:
                    return refreshed
        return None

    def _classify(self, inventory: PageInventory) -> str:
        if inventory.captcha_detected:
            return "captcha"
        if any(
            self.detector.is_registration_form(form, inventory)
            for form in inventory.forms
        ):
            return "registration"
        if any(
            self.detector.is_login_form(form, inventory)
            for form in inventory.forms
        ):
            return "login"
        if inventory.forms:
            return "form"
        return "page"

    def _page_result(
        self,
        page: PageRecord,
        finding_start: int,
        barrier_start: int,
        pages_before: set[str],
    ) -> dict:
        return {
            "page": page,
            "findings": self.context.findings[finding_start:],
            "barriers": self.context.barriers[barrier_start:],
            "new_pages": [
                current
                for url, current in self.context.pages.items()
                if url not in pages_before
            ],
            "authenticated": self.context.authenticated,
        }

    def _path_for(self, url: str) -> str:
        parts = urlsplit(url)
        target = urlsplit(self.context.target)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        if parts.fragment:
            path = f"{path}#{parts.fragment}"
        if parts.netloc.lower() != target.netloc.lower():
            return f"//{parts.netloc}{path}"
        return path
