from __future__ import annotations

from core.net import browser_cookies, build_client
from core.plugins import BasePlugin
from core.runtime import PluginResult
from core.runtime.entities import Barrier
from core.workflows import Authenticator


class LogoutInvalidationPlugin(BasePlugin):
    """Verify the server invalidates the session after logout."""

    NAME = "logout_invalidation"
    DESCRIPTION = "Verifies the session is invalidated server-side after logout"
    REQUIRES_AUTH = True

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done"):
            return False
        if not (self.context.settings.username and self.context.settings.password):
            return False
        if (
            self.context.settings.login_url
            or self.context.authentication_evidence.get("login_url")
        ):
            return True
        return any(
            self.detector.is_login_form(form, inventory)
            for form in inventory.forms
        )

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        auth = Authenticator(self.context, self.browser, self.detector)
        login_url = (
            self.context.settings.login_url
            or self.context.authentication_evidence.get("login_url")
            or page.url
        )
        if not list(auth.authenticated_route_candidates(exclude_url=login_url)):
            return result
        self.context.inputs[f"{self.NAME}_done"] = True
        timeout = float(settings["request_timeout"])

        if not auth.login(login_url=login_url):
            result.barriers.append(
                Barrier(
                    "authentication",
                    login_url,
                    "logout_invalidation could not authenticate",
                )
            )
            return result

        old_cookies = browser_cookies(self.context.driver)
        protected = auth.find_authenticated_page(
            exclude_url=login_url,
            timeout=timeout,
        )
        if protected is None:
            result.barriers.append(
                Barrier(
                    "coverage",
                    login_url,
                    "no authenticated-only page found to test logout",
                )
            )
            return result
        protected_url, protected_body = protected

        if not auth.logout():
            result.barriers.append(
                Barrier("coverage", login_url, "could not perform logout")
            )
            return result

        # Reuse the pre-logout session cookie: a properly invalidated session
        # must now be denied.
        with build_client(
            self.context.settings,
            timeout=timeout,
            follow_redirects=False,
            cookies=old_cookies,
        ) as client:
            try:
                reused = client.get(protected_url)
            except Exception:
                return result

        similarity = Authenticator.similarity(protected_body, reused.text)
        if reused.status_code == 200 and similarity >= float(
            settings["authenticated_content_similarity"]
        ):
            result.findings.append(
                self.finding(
                    title="Session not invalidated after logout",
                    description=(
                        "After logout, reusing the previous session cookie still "
                        "returned the authenticated page content."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": protected_url,
                        "reused_status": reused.status_code,
                        "content_similarity": round(similarity, 3),
                    },
                )
            )
        return result
