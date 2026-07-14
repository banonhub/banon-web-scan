from __future__ import annotations

from urllib.parse import urlsplit

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult


class CSPStrengthPlugin(BasePlugin):
    """Evaluate a present Content-Security-Policy for common weaknesses."""

    NAME = "csp_strength"
    DESCRIPTION = "Checks a present CSP for unsafe or missing directives"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("csp_strength_reported", set())
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

        header = response.headers.get("Content-Security-Policy")
        if not header:
            # A missing CSP is the headers plugin's job; only judge a present one.
            return result

        directives = self._parse(str(header))
        for code, message, severity in self._weaknesses(directives, settings):
            key = (origin, code)
            if key in reported:
                continue
            reported.add(key)
            result.findings.append(
                self.finding(
                    title=f"Weak Content-Security-Policy: {code}",
                    description=message,
                    severity=severity,
                    evidence={"url": page.url, "policy": header},
                )
            )
        return result

    def _weaknesses(self, directives: dict, settings: dict):
        found = []
        script = directives.get("script-src", directives.get("default-src", []))
        style = directives.get("style-src", directives.get("default-src", []))
        combined = set(script) | set(style)
        for token in settings["unsafe_tokens"]:
            if token in combined:
                found.append(
                    (
                        token.strip("'"),
                        f"The CSP allows {token}, which lets inline or "
                        "dynamically evaluated code run and largely defeats "
                        "the policy.",
                        settings["unsafe_severity"],
                    )
                )
        if "*" in set(script) | set(directives.get("default-src", [])):
            found.append(
                (
                    "wildcard-source",
                    "The CSP uses a '*' wildcard source for scripts, allowing "
                    "scripts to load from any origin.",
                    settings["wildcard_severity"],
                )
            )
        for directive in settings["recommended_directives"]:
            if directive not in directives:
                found.append(
                    (
                        f"missing-{directive}",
                        f"The CSP does not set '{directive}', leaving that "
                        "protection to the browser default.",
                        settings["missing_directive_severity"],
                    )
                )
        return found

    @staticmethod
    def _parse(header: str) -> dict:
        directives: dict[str, list[str]] = {}
        for part in header.split(";"):
            tokens = part.split()
            if not tokens:
                continue
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
        return directives

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
