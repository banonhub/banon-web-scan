from __future__ import annotations

from urllib.parse import urlsplit

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult


class SecurityHeadersPlugin(BasePlugin):
    """Check security response headers (CSP, HSTS, X-Frame-Options, ...)."""

    NAME = "headers"
    DESCRIPTION = "Checks security response headers (CSP, HSTS, X-Frame-Options)"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("headers_reported", set())
        origin = self._origin(page.url)

        try:
            with client_from_driver(
                self.context.driver,
                self.context.settings,
                timeout=float(settings["request_timeout"]),
            ) as client:
                response = client.get(page.url)
        except Exception:
            return result

        is_https = urlsplit(str(response.url)).scheme.lower() == "https"
        present = {name.lower() for name in response.headers.keys()}
        for check in settings["checks"]:
            header = check["header"]
            if check.get("https_only") and not is_https:
                continue
            if header.lower() in present:
                continue
            key = (origin, header.lower())
            if key in reported:
                continue
            reported.add(key)
            result.findings.append(
                self.finding(
                    title=f"Missing security header: {header}",
                    description=f"The response did not set the {header} header.",
                    severity=check["severity"],
                    evidence={"url": page.url, "header": header},
                )
            )
        return result

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
