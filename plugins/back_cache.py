from __future__ import annotations

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult
from core.runtime.entities import Barrier
from core.workflows import Authenticator


class BackCachePlugin(BasePlugin):
    """Verify sensitive pages are not restored via the Back button after logout."""

    NAME = "back_cache"
    DESCRIPTION = "Verifies sensitive pages are not cached in history after logout"
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
                    "back_cache could not authenticate",
                )
            )
            return result

        protected = auth.find_authenticated_page(
            exclude_url=login_url,
            timeout=timeout,
            minimum_length=int(settings["sensitive_content_min_length"]),
        )
        if protected is None:
            result.barriers.append(
                Barrier(
                    "coverage", login_url, "no authenticated content page found"
                )
            )
            return result
        protected_url, _ = protected

        try:
            sensitive = self.browser.open(protected_url)
        except Exception:
            return result
        marker = self._marker(
            sensitive.body_text, int(settings["sensitive_content_min_length"])
        )

        if not self._cache_control_ok(
            protected_url, timeout, settings["cache_directive_terms"]
        ):
            result.findings.append(
                self.finding(
                    title="Sensitive page lacks a no-store cache directive",
                    description=(
                        "The authenticated page did not set a no-store/no-cache "
                        "Cache-Control header, so it may be retained in history."
                    ),
                    severity=settings["missing_cache_control_severity"],
                    evidence={"url": protected_url},
                )
            )

        if not auth.logout():
            result.barriers.append(
                Barrier("coverage", login_url, "could not perform logout")
            )
            return result

        try:
            self.context.driver.back()
            restored = self.browser.inspect()
        except Exception:
            return result

        if marker and marker.lower() in (restored.body_text or "").lower():
            result.findings.append(
                self.finding(
                    title="Sensitive page restored from history after logout",
                    description=(
                        "Using the browser Back button after logout re-displayed "
                        "the authenticated page content from history."
                    ),
                    severity=settings["cached_after_logout_severity"],
                    evidence={"url": protected_url, "marker": marker[:60]},
                )
            )
        return result

    def _cache_control_ok(
        self, url: str, timeout: float, terms: list[str]
    ) -> bool:
        try:
            with client_from_driver(
                self.context.driver, self.context.settings, timeout=timeout
            ) as client:
                response = client.get(url)
        except Exception:
            return True  # cannot determine -> do not flag
        directive = response.headers.get("Cache-Control", "").lower()
        return any(term.lower() in directive for term in terms)

    @staticmethod
    def _marker(body: str, minimum_length: int) -> str:
        text = (body or "").strip()
        if len(text) < minimum_length:
            return ""
        chunk = " ".join(text.split()[:8])
        return chunk if len(chunk) >= 20 else ""
