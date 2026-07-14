from __future__ import annotations

import re
from urllib.parse import urlsplit

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult


class InfoHeadersPlugin(BasePlugin):
    """Flag response headers that disclose server or framework versions."""

    NAME = "info_headers"
    DESCRIPTION = "Flags response headers that leak server/framework versions"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("info_headers_reported", set())
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

        version = re.compile(settings["version_pattern"])
        for name in settings["disclosure_headers"]:
            value = response.headers.get(name)
            if not value:
                continue
            key = (origin, name.lower())
            if key in reported:
                continue
            reported.add(key)
            has_version = bool(version.search(str(value)))
            result.findings.append(
                self.finding(
                    title=f"Information disclosure header: {name}",
                    description=(
                        f"The response advertised '{name}: {value}', revealing "
                        "server or framework details that help an attacker "
                        "target known vulnerabilities for that software."
                    ),
                    severity=(
                        settings["version_severity"]
                        if has_version
                        else settings["severity"]
                    ),
                    evidence={
                        "url": page.url,
                        "header": name,
                        "value": value,
                        "version_disclosed": has_version,
                    },
                )
            )
        return result

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
