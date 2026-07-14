from __future__ import annotations

from core.browser.interaction_engine import InteractionEngine
from core.browser.page_inspector import PageInspector
from core.config.settings import ScannerSettings
from core.discovery.scope_policy import ScopePolicy
from core.runtime.entities import ControlTarget, PageInventory, PageRecord
from core.workflows.state_detector import StateDetector


class WorkflowEngine:
    """Explore explicitly safe UI transitions as a bounded state graph."""

    def __init__(
        self,
        actions: InteractionEngine,
        inspector: PageInspector,
        detector: StateDetector,
        settings: ScannerSettings,
    ):
        self.actions = actions
        self.inspector = inspector
        self.detector = detector
        self.settings = settings
        self.scope = (
            ScopePolicy(settings.target, settings)
            if settings.target
            else None
        )
        self.visited_states: set[str] = set()

    def safe_transition_pages(
        self,
        page: PageRecord,
        inventory: PageInventory,
    ) -> list[PageRecord]:
        """
        Return routes exposed by safe navigation controls.

        Controls are selected by behavior and safety signals, not by expected
        route names.
        """
        workflow = self.settings.get("workflows")
        if not workflow["activate_safe_controls"]:
            return []
        if page.depth >= int(workflow["maximum_steps"]):
            return []
        before = self.detector.fingerprint(inventory)
        if before in self.visited_states:
            return []
        if len(self.visited_states) >= int(workflow["maximum_states"]):
            return []
        self.visited_states.add(before)

        discovered: list[PageRecord] = []
        if workflow["explore_safe_forms"]:
            discovered.extend(
                self._safe_form_transitions(page, inventory, before)
            )
        candidates = self._navigation_candidates(inventory)
        for index, control in enumerate(candidates):
            try:
                self.actions.navigate(page.url)
                refreshed = self.inspector.inspect_current()
                match = self._match_refreshed_control(
                    control,
                    self._navigation_candidates(refreshed),
                    index,
                )
                if match is None:
                    continue
                self.actions.click(match)
                after = self.inspector.inspect_current()
                if after.url != inventory.url:
                    discovered.append(
                        PageRecord(
                            url=after.url,
                            path=after.url,
                            source="workflow",
                            authenticated=page.authenticated,
                            depth=page.depth + 1,
                        )
                    )
                    continue
                discovered.extend(
                    self._dynamic_panel_pages(page, inventory, before, after)
                )
            except Exception:
                continue
        try:
            self.actions.navigate(page.url)
        except Exception:
            pass
        return discovered

    def _navigation_candidates(
        self,
        inventory: PageInventory,
    ) -> list[ControlTarget]:
        workflow = self.settings.get("workflows")
        limit = int(workflow["maximum_transitions_per_page"])
        return [
            control
            for control in inventory.controls
            if self._is_navigation_candidate(control, workflow, inventory.url)
        ][:limit]

    def _is_navigation_candidate(
        self,
        control: ControlTarget,
        workflow: dict,
        current_url: str,
    ) -> bool:
        if not control.visible or not control.enabled:
            return False
        if control.form_id is not None:
            return False
        types = set(workflow["navigational_control_types"])
        if control.tag not in types and control.control_type not in types:
            return False
        if self._blocked_by_terms(control.semantic_text):
            return False
        if control.attributes.get("download"):
            return False
        href = control.attributes.get("href")
        if href and self.scope and not self.scope.is_allowed(href, current_url):
            return False
        return bool(control.semantic_text or control.attributes.get("href"))

    def _dynamic_panel_pages(
        self,
        page: PageRecord,
        inventory: PageInventory,
        before_fingerprint: str,
        after: PageInventory,
    ) -> list[PageRecord]:
        """Discover routes revealed by an in-place DOM change (panel/popup).

        A click that leaves the URL unchanged but alters the page fingerprint
        has opened something in place — a menu, drawer, modal, or a block of
        newly rendered fields. Wait for it to settle, re-inventory the page,
        fold the newly visible controls into ``inventory`` for downstream use,
        and return any in-scope routes the panel exposed.
        """
        workflow = self.settings.get("workflows")
        if not workflow.get("explore_dynamic_panels", True):
            return []
        if self.detector.fingerprint(after) == before_fingerprint:
            return []

        self._await_dom_stability()
        expanded = self.inspector.inspect_current()
        revealed = self._newly_revealed_candidates(inventory, expanded)
        self._merge_new_controls(inventory, expanded)

        limit = int(workflow.get("maximum_dynamic_panels", 6))
        discovered: list[PageRecord] = []
        seen: set[str] = set()
        for control in revealed[:limit]:
            href = control.attributes.get("href")
            if not href or href in seen:
                continue
            seen.add(href)
            discovered.append(
                PageRecord(
                    url=href,
                    path=href,
                    source="workflow_panel",
                    authenticated=page.authenticated,
                    depth=page.depth + 1,
                )
            )
        return discovered

    def _newly_revealed_candidates(
        self,
        inventory: PageInventory,
        expanded: PageInventory,
    ) -> list[ControlTarget]:
        """Navigation candidates present after the panel opened but not before."""
        known = {
            self._control_signature(control) for control in inventory.controls
        }
        return [
            control
            for control in self._navigation_candidates(expanded)
            if self._control_signature(control) not in known
        ]

    def _await_dom_stability(self) -> None:
        """Let a freshly opened panel finish rendering before re-inventorying."""
        wait = getattr(self.actions, "wait", None)
        if wait is None:
            return
        try:
            wait.dom_stable()
        except Exception:
            return

    @staticmethod
    def _merge_new_controls(
        inventory: PageInventory,
        expanded: PageInventory,
    ) -> None:
        """Add newly visible controls and forms to the page's own inventory."""
        known_controls = {control.element_id for control in inventory.controls}
        for control in expanded.controls:
            if control.element_id not in known_controls:
                inventory.controls.append(control)
                known_controls.add(control.element_id)
        known_forms = {form.element_id for form in inventory.forms}
        for form in expanded.forms:
            if form.element_id not in known_forms:
                inventory.forms.append(form)
                known_forms.add(form.element_id)

    def _match_refreshed_control(
        self,
        original: ControlTarget,
        refreshed: list[ControlTarget],
        original_index: int,
    ) -> ControlTarget | None:
        original_signature = self._control_signature(original)
        match = next(
            (
                control
                for control in refreshed
                if self._control_signature(control) == original_signature
            ),
            None,
        )
        if match is not None:
            return match
        if original_index < len(refreshed):
            return refreshed[original_index]
        return None

    @staticmethod
    def _control_signature(control: ControlTarget) -> tuple[str, ...]:
        return (
            control.tag,
            control.control_type,
            control.semantic_text,
            str(control.attributes.get("href", "")),
        )

    def _safe_form_transitions(
        self,
        page: PageRecord,
        inventory: PageInventory,
        before_fingerprint: str,
    ) -> list[PageRecord]:
        workflow = self.settings.get("workflows")
        eligible = set(workflow["fillable_control_types"])
        results: list[PageRecord] = []
        forms = [
            (index, form)
            for index, form in enumerate(inventory.forms)
            if not form.has_password
            and form.method == "get"
            and not self._blocked_by_terms(
                f"{form.action} {form.text}".lower(),
                include_state_changing_terms=True,
            )
        ][: int(workflow["maximum_transitions_per_page"])]

        for form_index, _ in forms:
            try:
                self.actions.navigate(page.url)
                refreshed = self.inspector.inspect_current()
                if form_index >= len(refreshed.forms):
                    continue
                form = refreshed.forms[form_index]
                controls = refreshed.controls_for_form(form)
                for control in controls:
                    if not control.required or control.control_type not in eligible:
                        continue
                    value = workflow["safe_values"].get(
                        control.control_type,
                        workflow["safe_values"]["default"],
                    )
                    self.actions.fill(control, value)
                self.actions.submit(form)
                after = self.inspector.inspect_current()
                if self.detector.fingerprint(after) == before_fingerprint:
                    continue
                results.append(
                    PageRecord(
                        url=after.url,
                        path=after.url,
                        source="workflow_form",
                        authenticated=page.authenticated,
                        depth=page.depth + 1,
                    )
                )
            except Exception:
                continue
        return results

    def _blocked_by_terms(
        self,
        semantic_text: str,
        *,
        include_state_changing_terms: bool = False,
    ) -> bool:
        if self.settings.allow_destructive:
            return False
        allowed = {term.lower() for term in self.settings.allow_destructive_terms}
        blocked = [
            term.lower()
            for term in self.settings.get("workflows", "blocked_control_terms")
            if term.lower() not in allowed
        ]
        safety = []
        if include_state_changing_terms:
            safety = [
                term.lower()
                for term in self.settings.get("safety", "state_changing_markers")
                if term.lower() not in allowed
            ]
        text = semantic_text.lower()
        return any(term in text for term in blocked + safety)
