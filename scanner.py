"""Command-line entry point for the Banon QA security testing framework.

The scanner runs entirely from command-line flags — there is no interactive
prompt. It attaches one shared browser, autonomously discovers same-origin
pages, applies whatever drop-in plugins are installed in ``plugins/`` to each
compatible page, and writes a JSON report.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import shutil
import sys
import time

from core.browser import create_driver
from core.config import parse_args
from core.reporting import HtmlReportWriter, ReportWriter
from core.runtime.scan_context import ScanContext
from core.runtime.scan_engine import ScanEngine


_ANSI = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}

_EVENT_STYLES = {
    "auth": ("green", "bold"),
    "browser": ("cyan",),
    "captcha": ("yellow", "bold"),
    "checks": ("magenta",),
    "discover": ("blue",),
    "error": ("red", "bold"),
    "fail": ("red", "bold"),
    "ready": ("green", "bold"),
    "run": ("yellow",),
    "scan": ("cyan",),
    "target": ("white", "bold"),
    "watch": ("green",),
}

_SEVERITY_STYLES = {
    "CRITICAL": ("red", "bold"),
    "HIGH": ("red",),
    "MEDIUM": ("yellow",),
    "LOW": ("blue",),
    "INFO": ("cyan",),
}


def _color_enabled(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return (
        hasattr(stream, "isatty")
        and stream.isatty()
        and os.environ.get("TERM", "") != "dumb"
    )


def _paint(text: str, *styles: str, stream=sys.stdout) -> str:
    if not _color_enabled(stream):
        return text
    codes = [_ANSI[style] for style in styles if style in _ANSI]
    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def _terminal_width() -> int:
    return max(60, min(shutil.get_terminal_size((88, 20)).columns, 120))


def _fit(value: object, width: int) -> str:
    text = str(value)
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return f"{text[:width - 3]}..."


def _event_line(event: str, message: str, detail: object = "", *, stream=None) -> None:
    stream = stream or sys.stdout
    styles = _EVENT_STYLES.get(event, ())
    label = _paint(f"[{event.upper():<8}]", *styles, stream=stream)
    detail_text = (
        f"  {_fit(detail, max(_terminal_width() - 38, 24))}"
        if detail
        else ""
    )
    print(f"{label} {message}{detail_text}", file=stream)


def _print_header(settings) -> None:
    width = min(_terminal_width(), 72)
    print()
    print(_paint("Banon Web Scan", "cyan", "bold"))
    print(_paint("-" * width, "dim"))
    print(f"  {'Target':<10} {settings.target}")
    print(
        f"  {'Browser':<10} "
        f"{'headless Chrome' if settings.headless else 'visible Chrome'}"
    )
    if settings.watch:
        print(f"  {'Watch':<10} browser actions slowed and highlighted")
    if settings.allow_destructive:
        print(
            f"  {'Safety':<10} "
            f"{_paint('destructive workflow actions ENABLED (all)', 'red', 'bold')}"
        )
    elif settings.allow_destructive_terms:
        allowed = ", ".join(settings.allow_destructive_terms)
        print(
            f"  {'Safety':<10} "
            f"{_paint(f'destructive actions ENABLED: {allowed}', 'red', 'bold')}"
        )
    print(f"  {'Output':<10} {settings.output}")
    if settings.captcha_pause:
        print(f"  {'Captcha':<10} interactive solve enabled (visible mode)")
    if settings.login_url:
        print(f"  {'Login URL':<10} {settings.login_url}")
    if settings.username:
        print(f"  {'Username':<10} {settings.username}")
    print()


def _print_error(message: str, detail: object = "") -> None:
    _event_line("error", message, detail, stream=sys.stderr)


def _configure_logging(settings, timestamp: str) -> str | None:
    """Set up the per-run file logger; never abort the scan on failure.

    Every run writes a log file to the configured ``logs`` directory, paired by
    timestamp with the JSON and HTML reports. ``--verbose`` lowers the file
    level from INFO to DEBUG. If the log file cannot be opened, the scan still
    runs — logging is a convenience, not a requirement.
    """
    logger = logging.getLogger("banon")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    try:
        evidence = settings.get("evidence")
        directory = Path(evidence["log_directory"]).expanduser()
        if not directory.is_absolute():
            directory = Path.cwd() / directory
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / evidence["log_filename"].format(timestamp=timestamp)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.DEBUG if settings.verbose else logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s",
            "%Y-%m-%dT%H:%M:%SZ",
        )
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return str(path)
    except Exception as exc:
        logger.addHandler(logging.NullHandler())
        _print_error("Could not open log file; continuing without one", exc)
        return None


def _make_progress(logger: logging.Logger, verbose: bool):
    """Build the progress callback: pretty console output plus file logging."""

    def progress(event: str, data: dict) -> None:
        if event == "plugins":
            names = ", ".join(data["names"]) or "none installed"
            _event_line("checks", names)
            logger.info("checks selected: %s", names)
        elif event == "discovery_probe":
            page = data["page"]
            if data["reachable"]:
                _event_line("discover", str(data["status_code"]), page.path)
                logger.info("discovered %s (%s)", page.path, data["status_code"])
            else:
                logger.debug(
                    "unreachable %s (%s) %s",
                    page.path,
                    data.get("status_code"),
                    data.get("error") or "",
                )
                if verbose:
                    _event_line(
                        "discover",
                        str(data.get("status_code") or "x"),
                        f"{page.path} (unreachable)",
                    )
        elif event == "page":
            _event_line("scan", data["page"].path)
            logger.info("scanning %s", data["page"].path)
        elif event == "plugin":
            _event_line("run", data["name"], data["page"].path)
            logger.info("run %s on %s", data["name"], data["page"].path)
        elif event == "authenticated":
            _event_line("auth", "authenticated session", data["url"])
            logger.info("authenticated at %s", data["url"])

    return progress


def _log_results(logger: logging.Logger, result: dict) -> None:
    """Write findings, coverage gaps, and a summary line to the run log."""
    for finding in result.get("findings", []):
        evidence = finding.get("evidence") or {}
        url = evidence.get("url", "") if isinstance(evidence, dict) else ""
        logger.info(
            "finding [%s] %s | plugin=%s %s",
            finding.get("severity", "INFO"),
            finding.get("title", ""),
            finding.get("plugin", "unknown"),
            url,
        )
    for barrier in result.get("barriers", []):
        logger.info(
            "coverage gap [%s] %s | %s",
            barrier.get("kind", ""),
            barrier.get("url", ""),
            barrier.get("detail", ""),
        )
    counts = Counter(
        finding.get("severity", "INFO")
        for finding in result.get("findings", [])
    )
    severity_summary = (
        ", ".join(
            f"{severity.lower()} {counts[severity]}"
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if counts.get(severity)
        )
        or "none"
    )
    logger.info(
        "scan complete | pages=%d/%d findings=%d (%s) gaps=%d",
        result.get("pages_scanned", 0),
        result.get("pages_discovered", 0),
        result.get("total_findings", 0),
        severity_summary,
        len(result.get("barriers", [])),
    )


def _format_findings(result: dict) -> str:
    total = int(result["total_findings"])
    if total == 0:
        return _paint("0", "green", "bold")

    counts = Counter(
        finding.get("severity", "INFO")
        for finding in result.get("findings", [])
    )
    parts = []
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = counts.get(severity)
        if not count:
            continue
        styles = _SEVERITY_STYLES.get(severity, ())
        parts.append(_paint(f"{severity.lower()} {count}", *styles))
    return f"{total} ({', '.join(parts)})"


def _print_summary(result: dict) -> None:
    print()
    print(_paint("Summary", "white", "bold"))
    print(_paint("-" * min(_terminal_width(), 72), "dim"))
    print(f"  {'Target':<10} {result['target']}")
    print(
        f"  {'Pages':<10} "
        f"{result['pages_scanned']} scanned / "
        f"{result['pages_discovered']} discovered"
    )
    print(f"  {'Findings':<10} {_format_findings(result)}")
    if result.get("barriers"):
        print(
            f"  {'Coverage':<10} "
            f"{_paint(str(len(result['barriers'])), 'yellow')} gap(s)"
        )
    print(f"  {'Report':<10} {result['report']}")
    if result.get("html_report"):
        print(f"  {'HTML':<10} {result['html_report']}")
    if result.get("log"):
        print(f"  {'Log':<10} {result['log']}")


def _captcha_handler(settings):
    """Build an interactive pause so a human can solve a detected CAPTCHA.

    Only usable when a real person can both see the browser and answer at the
    terminal: visible Chrome plus an interactive stdin. Otherwise there is no
    one to solve it, so the handler declines and the page stays a recorded
    coverage gap. The scanner never solves or bypasses the CAPTCHA itself — it
    only waits for the user to do so and then re-inspects the page.
    """

    def handle(barrier) -> bool:
        if barrier.kind != "captcha":
            return False
        if settings.headless or not (
            sys.stdin and sys.stdin.isatty()
        ):
            # No visible browser or no interactive terminal — cannot pause.
            return False
        _event_line("captcha", "CAPTCHA detected", barrier.url)
        print(
            _paint(
                "  Solve it in the browser window, then press Enter to "
                "continue — or type s + Enter to skip this page.",
                "yellow",
            )
        )
        try:
            answer = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        return answer not in {"s", "skip", "n", "no"}

    return handle


def main() -> int:
    settings = parse_args()
    if not settings.target:
        _print_error("A target is required", "--target <url>")
        return 2

    # One timestamp for the run so the log and both reports pair by filename.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = _configure_logging(settings, timestamp)
    logger = logging.getLogger("banon")
    logger.info(
        "Banon scan started | target=%s headless=%s watch=%s verbose=%s",
        settings.target,
        settings.headless,
        settings.watch,
        settings.verbose,
    )

    _print_header(settings)
    context = ScanContext(settings=settings)
    engine = ScanEngine(
        context,
        progress=_make_progress(logger, settings.verbose),
        barrier_handler=_captcha_handler(settings),
    )
    _event_line("target", "checking reachability", context.target)
    if not engine.target_reachable():
        _print_error("Target is not reachable", context.target)
        logger.error("target not reachable: %s", context.target)
        return 1
    _event_line("ready", "target is reachable")
    logger.info("target reachable: %s", context.target)

    if settings.watch:
        browser_mode = "watch mode"
    elif settings.headless:
        browser_mode = "headless"
    else:
        browser_mode = "visible"
    _event_line("browser", "starting browser", browser_mode)
    logger.info("starting browser: %s", browser_mode)
    driver = create_driver(settings)
    context.attach_driver(driver)
    try:
        result = engine.run()
    finally:
        driver.quit()

    result["report"] = ReportWriter(settings).write(result, timestamp=timestamp)
    result["html_report"] = HtmlReportWriter(settings).write(
        result, timestamp=timestamp
    )
    if log_path:
        result["log"] = log_path
    _log_results(logger, result)
    logger.info(
        "reports written | json=%s html=%s",
        result["report"],
        result["html_report"],
    )
    _print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
