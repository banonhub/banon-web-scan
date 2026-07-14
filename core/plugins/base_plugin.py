from abc import ABC, abstractmethod

from core.browser.base_page import BasePage
from core.config.list_provider import ListProvider
from core.runtime.entities import PageInventory, PageRecord
from core.runtime.results import Finding, PluginResult
from core.runtime.scan_context import ScanContext
from core.workflows.state_detector import StateDetector


class BasePlugin(ABC):
    """Page-agnostic contract implemented by every autonomous security check."""

    NAME = "unnamed_plugin"
    DESCRIPTION = "No description provided"
    # Set True by checks that must reach a logged-in state (need credentials).
    REQUIRES_AUTH = False

    def __init__(
        self,
        context: ScanContext,
        browser: BasePage,
        lists: ListProvider,
        detector: StateDetector,
    ):
        self.context = context
        self.browser = browser
        self.lists = lists
        self.detector = detector

    def supports(self, inventory: PageInventory) -> bool:
        """Return whether this plugin can usefully inspect this page inventory."""
        return True

    @abstractmethod
    def scan(
        self,
        page: PageRecord,
        inventory: PageInventory,
    ) -> PluginResult:
        """Run one bounded check against one inventoried page."""
        raise NotImplementedError

    def finding(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            description=description,
            severity=severity,
            evidence=evidence or {},
            plugin=self.NAME,
        )
