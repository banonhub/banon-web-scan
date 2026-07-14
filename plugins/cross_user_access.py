from __future__ import annotations

from core.net import browser_cookies, build_client
from core.plugins import BasePlugin
from core.runtime import PluginResult
from core.runtime.entities import Barrier
from core.workflows import Authenticator

from plugins._helpers import resource_like_url


class CrossUserAccessPlugin(BasePlugin):
    """Check whether a second user can read first-user resource URLs."""

    NAME = "cross_user_access"
    DESCRIPTION = "Checks User B cannot access User A resource URLs"
    REQUIRES_AUTH = True
    REQUIRES_SECONDARY_AUTH = True

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done"):
            return False
        return bool(
            self.context.authenticated
            and self.context.settings.secondary_username
            and self.context.settings.secondary_password
        )

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        auth = Authenticator(self.context, self.browser, self.detector)
        candidates = [
            record
            for record in auth.authenticated_route_candidates()
            if resource_like_url(record.url, settings["resource_url_patterns"])
        ][: int(settings["maximum_routes"])]
        if not candidates:
            return result

        login_url = (
            self.context.settings.login_url
            or self.context.authentication_evidence.get("login_url")
        )
        if not login_url:
            result.barriers.append(
                Barrier("coverage", page.url, "cross_user_access has no login URL")
            )
            return result

        primary_cookies = self.context.driver.get_cookies()
        primary_cookie_map = browser_cookies(self.context.driver)
        secondary_cookie_map = self._secondary_cookies(auth, login_url, primary_cookies)
        if not secondary_cookie_map:
            result.barriers.append(
                Barrier(
                    "authentication",
                    login_url,
                    "cross_user_access could not authenticate secondary user",
                )
            )
            return result
        self.context.inputs[f"{self.NAME}_done"] = True

        timeout = float(settings["request_timeout"])
        threshold = float(settings["content_similarity_threshold"])
        with build_client(
            self.context.settings,
            timeout=timeout,
            follow_redirects=False,
            cookies=primary_cookie_map,
        ) as primary, build_client(
            self.context.settings,
            timeout=timeout,
            follow_redirects=False,
            cookies=secondary_cookie_map,
        ) as secondary:
            for record in candidates:
                try:
                    first = primary.get(record.url)
                    second = secondary.get(record.url)
                except Exception:
                    continue
                if first.status_code != 200 or second.status_code != 200:
                    continue
                similarity = Authenticator.similarity(first.text, second.text)
                if similarity >= threshold:
                    result.findings.append(
                        self.finding(
                            title="Cross-user resource accessible",
                            description=(
                                "A resource URL learned as the primary user "
                                "returned similar content for the secondary user."
                            ),
                            severity=settings["severity"],
                            evidence={
                                "url": record.url,
                                "primary_status": first.status_code,
                                "secondary_status": second.status_code,
                                "content_similarity": round(similarity, 3),
                            },
                        )
                    )
        return result

    def _secondary_cookies(self, auth, login_url: str, primary_cookies: list[dict]):
        try:
            self.context.driver.delete_all_cookies()
            logged_in = auth.login(
                login_url=login_url,
                username=self.context.settings.secondary_username,
                password=self.context.settings.secondary_password,
            )
            cookies = browser_cookies(self.context.driver) if logged_in else {}
        finally:
            self._restore_cookies(primary_cookies)
        return cookies

    def _restore_cookies(self, cookies: list[dict]) -> None:
        try:
            self.context.driver.delete_all_cookies()
            self.browser.open(self.context.target)
            for cookie in cookies:
                restored = {
                    key: value
                    for key, value in cookie.items()
                    if key
                    in {
                        "name",
                        "value",
                        "path",
                        "domain",
                        "secure",
                        "httpOnly",
                        "expiry",
                        "sameSite",
                    }
                }
                try:
                    self.context.driver.add_cookie(restored)
                except Exception:
                    continue
        except Exception:
            return
