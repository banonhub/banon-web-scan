from __future__ import annotations

from core.net import build_client
from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import csrf_like_controls, hidden_token_values, state_changing_forms


class CsrfUniquenessPlugin(BasePlugin):
    """Check whether CSRF-like tokens appear static across fresh sessions."""

    NAME = "csrf_uniqueness"
    DESCRIPTION = "Checks CSRF-like tokens are not static across sessions"

    def supports(self, inventory) -> bool:
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        forms = state_changing_forms(inventory, skip_terms=settings["skip_terms"])
        return any(
            csrf_like_controls(
                inventory.controls_for_form(form),
                settings["token_terms"],
            )
            for form in forms
        )

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        responses = []
        try:
            for _ in range(int(settings["sample_count"])):
                with build_client(
                    self.context.settings,
                    timeout=float(settings["request_timeout"]),
                    follow_redirects=True,
                ) as client:
                    responses.append(client.get(page.url).text)
        except Exception:
            return result

        samples = [
            hidden_token_values(body, settings["token_terms"])
            for body in responses
        ]
        common_names = set(samples[0]) if samples else set()
        for sample in samples[1:]:
            common_names.intersection_update(sample)

        reused = [
            name
            for name in common_names
            if len({sample[name] for sample in samples}) == 1
            and len(samples[0][name]) >= int(settings["minimum_token_length"])
        ]
        if reused:
            result.findings.append(
                self.finding(
                    title="CSRF token appears static across sessions",
                    description=(
                        "A CSRF-like hidden field had the same value across "
                        "fresh unauthenticated requests."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "token_names": reused,
                        "samples": len(samples),
                    },
                )
            )
        return result
