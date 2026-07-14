from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from core.config.settings import ScannerSettings
from core.runtime.entities import Barrier, PageInventory, PageRecord
from core.runtime.results import Finding


@dataclass(slots=True)
class ScanContext:
    """Typed owner of all mutable state for one browser-backed scan."""

    settings: ScannerSettings
    target: str | None = None
    driver: Any | None = field(default=None, repr=False)
    authenticated: bool = False
    authentication_evidence: dict[str, Any] = field(default_factory=dict)
    current_page: PageRecord | None = None
    current_inventory: PageInventory | None = None
    pages: OrderedDict[str, PageRecord] = field(default_factory=OrderedDict)
    findings: list[Finding] = field(default_factory=list)
    barriers: list[Barrier] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    completed_plugin_pages: set[tuple[str, str, bool]] = field(
        default_factory=set
    )

    def __post_init__(self):
        if self.target is None:
            self.target = self.settings.target

    def attach_driver(self, driver: Any) -> None:
        self.driver = driver

    def add_page(self, page: PageRecord) -> bool:
        existing = self.pages.get(page.url)
        if existing is None:
            self.pages[page.url] = page
            return True
        if page.authenticated and not existing.authenticated:
            page.status = "pending"
            self.pages[page.url] = page
            return True
        return False

    def next_pending_page(self) -> PageRecord | None:
        for page in self.pages.values():
            if page.status == "pending":
                page.status = "scanning"
                return page
        return None

    def mark_authenticated(self, evidence: dict[str, Any]) -> None:
        if not self.authenticated:
            self.completed_plugin_pages.clear()
        self.authenticated = True
        self.authentication_evidence.update(evidence)

    def promote_pages_to_authenticated(
        self,
        *,
        queue_for_scan: bool,
    ) -> None:
        """Make routes discovered before login available in the new state."""
        for page in self.pages.values():
            if page.authenticated:
                continue
            page.authenticated = True
            page.status = "pending" if queue_for_scan else "discovered"

    def record_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def record_barriers(self, barriers: list[Barrier]) -> None:
        self.barriers.extend(barriers)
