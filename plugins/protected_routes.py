from __future__ import annotations

from core.net import browser_cookies, build_client
from core.plugins import BasePlugin
from core.runtime import PluginResult
from core.runtime.entities import Barrier
from core.workflows import Authenticator


class ProtectedRoutesPlugin(BasePlugin):
    """Verify routes that serve authenticated content deny anonymous access."""

    NAME = "protected_routes"
    DESCRIPTION = "Verifies protected routes deny access when logged out"
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
        route_records = list(
            auth.authenticated_route_candidates(exclude_url=login_url)
        )[: int(settings["maximum_routes"])]
        if not route_records:
            return result

        self.context.inputs[f"{self.NAME}_done"] = True

        if not auth.login(login_url=login_url):
            result.barriers.append(
                Barrier(
                    "authentication",
                    login_url,
                    "protected_routes could not authenticate",
                )
            )
            return result

        auth_cookies = browser_cookies(self.context.driver)
        timeout = float(settings["request_timeout"])
        denied = set(settings["denied_status_codes"])
        threshold = float(settings["content_similarity_threshold"])

        with build_client(
            self.context.settings,
            timeout=timeout,
            follow_redirects=False,
        ) as anonymous, build_client(
            self.context.settings,
            timeout=timeout,
            follow_redirects=False,
            cookies=auth_cookies,
        ) as authenticated:
            for record in route_records:
                url = record.url
                try:
                    with_auth = authenticated.get(url)
                    without_auth = anonymous.get(url)
                except Exception:
                    continue
                # Only routes that actually serve authenticated content matter.
                if with_auth.status_code != 200:
                    continue
                if without_auth.status_code in denied:
                    continue  # correctly protected
                if (
                    without_auth.status_code == 200
                    and Authenticator.similarity(with_auth.text, without_auth.text)
                    >= threshold
                ):
                    result.findings.append(
                        self.finding(
                            title="Protected route accessible without authentication",
                            description=(
                                "A route that serves authenticated content also "
                                "returned the same content without a session."
                            ),
                            severity=settings["severity"],
                            evidence={
                                "url": url,
                                "authenticated_status": with_auth.status_code,
                                "anonymous_status": without_auth.status_code,
                            },
                        )
                    )
        return result
