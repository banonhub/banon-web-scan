from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult
from core.runtime.entities import Barrier
from core.workflows import Authenticator


class SessionRotationPlugin(BasePlugin):
    """Verify the session identifier changes across the login boundary."""

    NAME = "session_rotation"
    DESCRIPTION = "Verifies the session cookie changes after login (fixation)"
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
        self.context.inputs[f"{self.NAME}_done"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        auth = Authenticator(self.context, self.browser, self.detector)
        login_url = (
            self.context.settings.login_url
            or self.context.authentication_evidence.get("login_url")
            or page.url
        )
        terms = settings["session_cookie_name_terms"]

        try:
            self.browser.open(login_url)
        except Exception:
            result.barriers.append(
                Barrier("navigation", login_url, "could not open login page")
            )
            return result
        before = auth.session_cookie(terms)
        before_value = before.get("value") if before else None

        if not auth.login(login_url=login_url):
            result.barriers.append(
                Barrier(
                    "authentication",
                    login_url,
                    "session_rotation could not authenticate",
                )
            )
            return result

        after = auth.session_cookie(terms)
        after_value = after.get("value") if after else None
        if before_value and after_value and before_value == after_value:
            result.findings.append(
                self.finding(
                    title="Session identifier not rotated after login",
                    description=(
                        "The session cookie kept the same value across the "
                        "login boundary, which enables session fixation."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": login_url,
                        "cookie": (after or {}).get("name"),
                        "unchanged_value": True,
                    },
                )
            )
        return result
