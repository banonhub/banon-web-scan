from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.plugins import BasePlugin
from core.runtime import PluginResult


class UrlSecretsPlugin(BasePlugin):
    """Flag session tokens or credentials carried in URL query strings."""

    NAME = "url_secrets"
    DESCRIPTION = "Flags secrets (tokens, passwords, keys) carried in URLs"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("url_secrets_reported", set())
        terms = [term.lower() for term in settings["sensitive_param_terms"]]

        for url in [page.url, *inventory.links]:
            parts = urlsplit(url)
            if not parts.query:
                continue
            for name, value in parse_qsl(parts.query):
                if not value or not self._is_sensitive(name, terms):
                    continue
                key = (parts.netloc.lower(), parts.path, name.lower())
                if key in reported:
                    continue
                reported.add(key)
                result.findings.append(
                    self.finding(
                        title="Sensitive data in URL",
                        description=(
                            f"The query parameter '{name}' carries what looks "
                            "like a secret in the URL. URLs are stored in "
                            "browser history, server logs, and the Referer "
                            "header, so secrets placed in them leak easily."
                        ),
                        severity=settings["severity"],
                        evidence={
                            "url": self._redact(url, name),
                            "parameter": name,
                        },
                    )
                )
        return result

    @staticmethod
    def _is_sensitive(name: str, terms: list[str]) -> bool:
        lowered = name.lower()
        tokens = set(re.split(r"[^a-z0-9]+", lowered))
        for term in terms:
            if len(term) >= 5:
                if term in lowered:
                    return True
            elif term in tokens:
                return True
        return False

    @staticmethod
    def _redact(url: str, target: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        redacted = [
            (name, "***" if name == target else value) for name, value in pairs
        ]
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(redacted),
                parts.fragment,
            )
        )
