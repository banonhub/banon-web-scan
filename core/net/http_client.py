from __future__ import annotations

import httpx

from core.config.settings import ScannerSettings


# The single class every caller catches, so plugins never import httpx names
# directly. It covers connect/read/timeout/transport failures.
request_error = httpx.RequestError


def http2_available() -> bool:
    """HTTP/2 needs the optional `h2` package. Detect it so a missing extra
    downgrades to HTTP/1.1 instead of raising when a client is built."""
    try:
        import h2  # noqa: F401
    except Exception:
        return False
    return True


def browser_cookies(driver) -> dict[str, str]:
    """Read the live Selenium session cookies as a plain name→value mapping."""
    return {
        cookie.get("name", ""): cookie.get("value", "")
        for cookie in driver.get_cookies()
        if cookie.get("name")
    }


def build_client(
    settings: ScannerSettings,
    *,
    timeout: float | None = None,
    follow_redirects: bool = True,
    cookies: dict[str, str] | None = None,
) -> httpx.Client:
    """Build an httpx client using the central `network` configuration.

    `follow_redirects` defaults to True to match the previous requests-based
    behavior; callers that inspect a redirect (open redirect, access control,
    file traversal) pass False explicitly.
    """
    network = settings.get("network")
    resolved_timeout = (
        float(network["default_timeout"]) if timeout is None else float(timeout)
    )
    use_http2 = bool(network["http2"]) and http2_available()
    headers = {}
    user_agent = network.get("user_agent")
    if user_agent:
        headers["User-Agent"] = str(user_agent)
    return httpx.Client(
        timeout=resolved_timeout,
        follow_redirects=follow_redirects,
        http2=use_http2,
        verify=bool(network["verify_tls"]),
        cookies=cookies or {},
        headers=headers,
    )


def client_from_driver(
    driver,
    settings: ScannerSettings,
    *,
    timeout: float | None = None,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Client that reuses the browser's authenticated session cookies."""
    return build_client(
        settings,
        timeout=timeout,
        follow_redirects=follow_redirects,
        cookies=browser_cookies(driver),
    )
