from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from core.net import build_client
from core.plugins import BasePlugin
from core.runtime import PluginResult


class HTTPSEnforcementPlugin(BasePlugin):
    """Verify pages use HTTPS and that HTTP redirects up to HTTPS."""

    NAME = "https"
    DESCRIPTION = "Verifies pages use HTTPS and that HTTP redirects to HTTPS"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("https_reported", set())
        parts = urlsplit(page.url)
        sensitive = self._is_sensitive(inventory, settings)

        if parts.scheme.lower() == "http":
            key = ("http_page", parts.netloc.lower(), parts.path)
            if key not in reported:
                reported.add(key)
                result.findings.append(
                    self.finding(
                        title="Page served over HTTP",
                        description=(
                            "The page was served over an unencrypted HTTP "
                            "connection."
                        ),
                        severity=(
                            settings["sensitive_http_severity"]
                            if sensitive
                            else settings["http_page_severity"]
                        ),
                        evidence={"url": page.url, "sensitive": sensitive},
                    )
                )
            return result

        # The page is HTTPS: confirm the HTTP origin redirects up to HTTPS.
        key = ("no_redirect", parts.netloc.lower())
        if key in reported:
            return result
        http_url = urlunsplit(("http", parts.netloc, parts.path or "/", "", ""))
        try:
            with build_client(
                self.context.settings,
                timeout=float(settings["request_timeout"]),
                follow_redirects=False,
            ) as client:
                response = client.get(http_url)
        except Exception:
            return result

        location = response.headers.get("Location", "")
        redirects_to_https = (
            300 <= response.status_code < 400
            and urlsplit(location).scheme.lower() == "https"
        )
        if not redirects_to_https and response.status_code < 400:
            reported.add(key)
            result.findings.append(
                self.finding(
                    title="HTTP does not redirect to HTTPS",
                    description=(
                        "The HTTP version of the site responded without "
                        "redirecting to HTTPS, allowing a downgrade."
                    ),
                    severity=settings["missing_redirect_severity"],
                    evidence={
                        "url": http_url,
                        "status_code": response.status_code,
                        "location": location,
                    },
                )
            )
        return result

    @staticmethod
    def _is_sensitive(inventory, settings: dict) -> bool:
        secret_types = set(settings["sensitive_control_types"])
        if any(form.has_password for form in inventory.forms):
            return True
        return any(
            control.control_type in secret_types
            for control in inventory.controls
        )
