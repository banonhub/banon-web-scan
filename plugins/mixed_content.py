from __future__ import annotations

from urllib.parse import urlsplit

from core.plugins import BasePlugin
from core.runtime import PluginResult


class MixedContentPlugin(BasePlugin):
    """Find HTTP sub-resources loaded by an HTTPS page (mixed content)."""

    NAME = "mixed_content"
    DESCRIPTION = "Finds HTTP resources loaded by an HTTPS page (mixed content)"

    _DESCRIPTIONS = {
        "active": (
            "An HTTPS page loaded active resources (scripts, iframes, or "
            "stylesheets) over unencrypted HTTP. These can be modified in "
            "transit to run attacker-controlled code in the page."
        ),
        "passive": (
            "An HTTPS page loaded passive resources (images or media) over "
            "unencrypted HTTP, which leaks requests and weakens the page's "
            "integrity."
        ),
    }

    def supports(self, inventory) -> bool:
        return urlsplit(inventory.url).scheme.lower() == "https"

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("mixed_content_reported", set())

        try:
            resources = self.context.driver.execute_script(self._collect_script())
        except Exception:
            return result

        active_tags = set(settings["active_tags"])
        active: list[dict] = []
        passive: list[dict] = []
        for item in resources or []:
            url = str(item.get("url", ""))
            if not url.lower().startswith("http://"):
                continue
            tag = str(item.get("tag", ""))
            entry = {"tag": tag, "url": url}
            (active if tag in active_tags else passive).append(entry)

        origin = self._origin(inventory.url)
        limit = int(settings["maximum_matches"])
        for kind, items, severity_key in (
            ("active", active, "active_severity"),
            ("passive", passive, "passive_severity"),
        ):
            if not items:
                continue
            key = (origin, kind)
            if key in reported:
                continue
            reported.add(key)
            result.findings.append(
                self.finding(
                    title=f"Mixed content: {kind} HTTP resources on an HTTPS page",
                    description=self._DESCRIPTIONS[kind],
                    severity=settings[severity_key],
                    evidence={"page": inventory.url, "resources": items[:limit]},
                )
            )
        return result

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"

    @staticmethod
    def _collect_script() -> str:
        return """
        const out = [];
        const add = (tag, url) => { if (url) out.push({tag: tag, url: url}); };
        document.querySelectorAll('script[src]')
          .forEach(e => add('script', e.src));
        document.querySelectorAll('link[rel~="stylesheet"][href]')
          .forEach(e => add('link', e.href));
        document.querySelectorAll('iframe[src]')
          .forEach(e => add('iframe', e.src));
        document.querySelectorAll('object[data]')
          .forEach(e => add('object', e.data));
        document.querySelectorAll('embed[src]')
          .forEach(e => add('embed', e.src));
        document.querySelectorAll('img[src]')
          .forEach(e => add('img', e.src));
        document.querySelectorAll('video[src], audio[src], source[src]')
          .forEach(e => add(e.tagName.toLowerCase(), e.src));
        return out;
        """
