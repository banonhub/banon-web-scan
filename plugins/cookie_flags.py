from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult


class CookieFlagsPlugin(BasePlugin):
    """Check session/auth cookies for Secure, HttpOnly, and SameSite."""

    NAME = "cookie_flags"
    DESCRIPTION = "Checks session/auth cookies for Secure, HttpOnly, and SameSite"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault("cookie_flags_reported", set())
        terms = [term.lower() for term in settings["session_cookie_name_terms"]]
        check_all = bool(settings["check_all_cookies"])

        checks = (
            ("secure", "secure", "Cookie is missing the Secure flag",
             "The cookie can be transmitted over unencrypted HTTP.",
             settings["missing_secure_severity"]),
            ("httpOnly", "httponly", "Cookie is missing the HttpOnly flag",
             "Client-side JavaScript can read the cookie.",
             settings["missing_httponly_severity"]),
            ("sameSite", "samesite", "Cookie has no SameSite policy",
             "The cookie has no browser-enforced cross-site request policy.",
             settings["missing_samesite_severity"]),
        )

        for cookie in self.context.driver.get_cookies():
            name = str(cookie.get("name", ""))
            if not check_all and not any(term in name.lower() for term in terms):
                continue
            evidence = {
                "url": page.url,
                "cookie": name,
                "secure": bool(cookie.get("secure")),
                "http_only": bool(cookie.get("httpOnly")),
                "same_site": cookie.get("sameSite"),
            }
            for attribute, flag, title, description, severity in checks:
                if cookie.get(attribute):
                    continue
                key = (name, flag)
                if key in reported:
                    continue
                reported.add(key)
                result.findings.append(
                    self.finding(
                        title=title,
                        description=description,
                        severity=severity,
                        evidence=evidence,
                    )
                )
        return result
