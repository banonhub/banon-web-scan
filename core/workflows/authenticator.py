from __future__ import annotations

from difflib import SequenceMatcher

from core.browser.base_page import BasePage
from core.net import browser_cookies, build_client
from core.runtime.entities import ControlTarget, FormTarget, PageInventory
from core.workflows.state_detector import StateDetector


class Authenticator:
    """Reusable login/logout/session helpers built on the shared browser.

    Stateful QA checks (session rotation, logout invalidation, back-button
    cache, protected-route access) use this to reach and leave an authenticated
    state without each one reimplementing form handling. It reuses
    ``StateDetector`` for login-form detection and authentication-change
    confirmation, so it carries no target-specific selectors or route names.
    """

    def __init__(self, context, browser: BasePage, detector: StateDetector):
        self.context = context
        self.driver = context.driver
        self.settings = context.settings
        self.browser = browser
        self.detector = detector

    # -- credentials -------------------------------------------------------
    def credentials(self) -> tuple[str, str] | None:
        username = self.settings.username
        password = self.settings.password
        if not username or not password:
            return None
        return username, password

    # -- login -------------------------------------------------------------
    def login_form(self, inventory: PageInventory) -> FormTarget | None:
        return next(
            (
                form
                for form in inventory.forms
                if self.detector.is_login_form(form, inventory)
            ),
            None,
        )

    def login(
        self,
        login_url: str | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
    ) -> bool:
        """Submit the login form with the configured credentials and confirm
        an authenticated transition. Returns False if credentials are missing,
        no login form is present, or authentication did not change."""
        creds = (
            (username, password)
            if username is not None and password is not None
            else self.credentials()
        )
        if creds is None:
            return False
        username, password = creds
        url = login_url or self.settings.login_url
        try:
            inventory = self.browser.open(url) if url else self.browser.inspect()
        except Exception:
            return False
        form = self.login_form(inventory)
        if form is None:
            return False
        controls = inventory.controls_for_form(form)
        identity = self._identity_control(controls)
        secret = self._secret_control(controls)
        if identity is None or secret is None:
            return False
        before = self.detector.capture(inventory)
        try:
            self.browser.fill(identity, username)
            self.browser.fill(secret, password)
            self.browser.submit(form)
            after_inventory = self.browser.inspect()
        except Exception:
            return False
        after = self.detector.capture(after_inventory)
        return self.detector.authentication_changed(before, after)

    def _identity_control(
        self, controls: list[ControlTarget]
    ) -> ControlTarget | None:
        types = self.settings.get("authentication", "identity_control_types")
        terms = self.settings.get("authentication", "identity_semantic_terms")
        match = next(
            (
                control
                for control in controls
                if control.control_type in types
                and any(term.lower() in control.semantic_text for term in terms)
            ),
            None,
        )
        if match is not None:
            return match
        return next(
            (control for control in controls if control.control_type in types),
            None,
        )

    def _secret_control(
        self, controls: list[ControlTarget]
    ) -> ControlTarget | None:
        types = self.settings.get("inspection", "secret_control_types")
        return next(
            (
                control
                for control in controls
                if control.control_type in types and control.enabled
            ),
            None,
        )

    # -- logout ------------------------------------------------------------
    def logout(self) -> bool:
        """Best-effort logout: click a control or follow a link whose text
        matches the configured logout terms. Returns whether one was used."""
        terms = [
            term.lower()
            for term in self.settings.get(
                "authentication", "logout_semantic_terms"
            )
        ]
        try:
            inventory = self.browser.inspect()
        except Exception:
            return False
        control = next(
            (
                control
                for control in inventory.controls
                if control.visible
                and control.enabled
                and any(term in control.semantic_text for term in terms)
            ),
            None,
        )
        if control is not None:
            try:
                self.browser.actions.click(control)
                return True
            except Exception:
                pass
        for link in inventory.links:
            if any(term in link.lower() for term in terms):
                try:
                    self.browser.open(link)
                    return True
                except Exception:
                    continue
        return False

    # -- cookies / session -------------------------------------------------
    def session_cookie(self, name_terms: list[str]) -> dict | None:
        terms = [term.lower() for term in name_terms]
        for cookie in self.driver.get_cookies():
            if any(term in str(cookie.get("name", "")).lower() for term in terms):
                return cookie
        return None

    # -- authenticated page discovery -------------------------------------
    def find_authenticated_page(
        self,
        *,
        exclude_url: str,
        timeout: float,
        minimum_length: int = 0,
    ) -> tuple[str, str] | None:
        """Find a route that serves real content with the current session but
        is denied without it. Returns (url, authenticated_body) or None.

        Must be called while authenticated."""
        cookies = browser_cookies(self.driver)
        with build_client(
            self.settings, timeout=timeout, follow_redirects=False, cookies=cookies
        ) as authed, build_client(
            self.settings, timeout=timeout, follow_redirects=False
        ) as anon:
            for page in self.authenticated_route_candidates(
                exclude_url=exclude_url
            ):
                try:
                    with_auth = authed.get(page.url)
                    without_auth = anon.get(page.url)
                except Exception:
                    continue
                if (
                    with_auth.status_code == 200
                    and len(with_auth.text.strip()) >= minimum_length
                    and without_auth.status_code != 200
                ):
                    return page.url, with_auth.text
        return None

    def authenticated_route_candidates(
        self,
        *,
        exclude_url: str | None = None,
    ):
        """Routes learned from the authenticated browser state."""
        authenticated_sources = {
            "authentication",
            "authenticated_workflow",
            "authenticated_form",
        }
        for page in self.context.pages.values():
            if exclude_url and page.url == exclude_url:
                continue
            if page.authenticated and page.source in authenticated_sources:
                yield page

    @staticmethod
    def similarity(first: str, second: str) -> float:
        return SequenceMatcher(None, first or "", second or "").ratio()
