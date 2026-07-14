import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.config.list_provider import ListProvider
from core.config.settings import ScannerSettings
from core.config.validator import validate_defaults


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULTS_PATH = PROJECT_ROOT / "data" / "defaults.json"

REQUIRED_SECTIONS = {
    "application",
    "browser",
    "network",
    "scope",
    "discovery",
    "inspection",
    "interaction",
    "authentication",
    "workflows",
    "safety",
    "plugins",
    "lists",
    "evidence",
}


def load_defaults(path: Path = DEFAULTS_PATH) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            defaults = json.load(file)
    except FileNotFoundError as exc:
        raise SystemExit(f"[ERROR] Defaults file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] Invalid defaults JSON: {exc}") from exc

    missing = sorted(REQUIRED_SECTIONS.difference(defaults))
    if missing:
        raise SystemExit(
            "[ERROR] defaults.json is missing sections: " + ", ".join(missing)
        )
    try:
        validate_defaults(defaults)
    except ValueError as exc:
        raise SystemExit(f"[ERROR] {exc}") from exc
    return defaults


def normalize_target(value: str) -> str:
    """Accept a bare host or full URL and return a canonical origin/path."""
    value = value.strip()
    if "://" not in value:
        value = f"http://{value}"
    parts = urlsplit(value)
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc,
            parts.path.rstrip("/"),
            parts.query,
            "",
        )
    )


def _destructive_terms(defaults: dict[str, Any]) -> list[str]:
    """Every term that marks a control as destructive, deduped in order.

    This is the union of the workflow block list and the safety state-changing
    markers, and it is exactly the set a user may selectively allow.
    """
    workflows = defaults.get("workflows", {})
    safety = defaults.get("safety", {})
    terms = [
        *workflows.get("blocked_control_terms", []),
        *safety.get("state_changing_markers", []),
    ]
    return list(dict.fromkeys(term.lower() for term in terms))


def _resolve_destructive(
    selected: list[str] | None,
    available: list[str],
) -> tuple[bool, list[str]]:
    """Map the raw --allow-destructive value to (allow_all, allowed_terms).

    ``None``  -> flag absent: nothing is allowed.
    ``[]``    -> bare flag:   everything is allowed.
    ``[...]`` -> allow only the listed terms; unknown terms raise a clear error.
    """
    if selected is None:
        return False, []
    if not selected:
        return True, []
    known = set(available)
    requested = list(dict.fromkeys(term.lower() for term in selected))
    unknown = [term for term in requested if term not in known]
    if unknown:
        raise SystemExit(
            "[ERROR] Unknown --allow-destructive term(s): "
            f"{', '.join(unknown)}. Available: {', '.join(available)}"
        )
    return False, requested


def _discover_plugin_choices(defaults: dict[str, Any]) -> dict[str, str]:
    """Discover installed plugins so each gets its own ``--<name>`` flag.

    Returns an ordered ``{name: description}`` map. Best-effort: if discovery
    fails for any reason, no per-plugin flags are added and ``--scan`` still
    works. Importing this lazily keeps the config package free of a plugin
    dependency at module load time.
    """
    from core.plugins.plugin_manager import PluginManager

    plugin_settings = ScannerSettings(
        target=None,
        scan=[defaults["plugins"]["all_token"]],
        headless=bool(defaults["browser"]["headless"]),
        watch=False,
        timeout=int(defaults["browser"]["page_load_timeout"]),
        output=defaults["evidence"]["output_directory"],
        defaults=defaults,
        project_root=PROJECT_ROOT,
    )
    try:
        library = PluginManager(plugin_settings).discover()
    except Exception:
        return {}
    return {name: library[name] for name in sorted(library)}


def _print_check_list(plugin_classes: dict) -> None:
    """Human-readable listing of every check and its own flag."""
    print("Available checks - each has its own --<flag>:\n")
    for name, plugin in plugin_classes.items():
        tags = []
        if getattr(plugin, "REQUIRES_AUTH", False):
            tags.append("needs --username/--password")
        if getattr(plugin, "REQUIRES_SECONDARY_AUTH", False):
            tags.append("needs --secondary-username/--secondary-password")
        tag = f"  [{'; '.join(tags)}]" if tags else ""
        print(f"  --{name}{tag}")
        print(f"      {plugin.DESCRIPTION}")
    print()
    print("Run all checks:   omit the check flags (default).")
    print("Run some checks:  pass one or more --<flag>, e.g. --headers --https")
    print("                  or use --scan <name> [<name> ...].")


def parse_args(args=None) -> ScannerSettings:
    defaults = load_defaults()
    application = defaults["application"]
    browser = defaults["browser"]
    plugins = defaults["plugins"]
    evidence = defaults["evidence"]
    destructive_terms = _destructive_terms(defaults)
    plugin_choices = _discover_plugin_choices(defaults)

    parser = argparse.ArgumentParser(
        prog=application["command_name"],
        description=application["description"],
        epilog="Tip: run with --list-checks for a description of every check.",
        allow_abbrev=False,
    )
    parser.add_argument("--target")
    parser.add_argument(
        "--list-checks",
        dest="list_checks",
        action="store_true",
        help="List all checks with descriptions and exit.",
    )
    parser.add_argument(
        "--scan",
        nargs="+",
        default=None,
        help="Run these plugins by name, or 'all'. Omit to run every plugin.",
    )
    browser_modes = parser.add_mutually_exclusive_group()
    browser_modes.add_argument(
        "--headless",
        action="store_true",
        default=browser["headless"],
        help="Run Chrome hidden in headless mode.",
    )
    browser_modes.add_argument(
        "--watch",
        action="store_true",
        help=(
            "Show browser actions slowly with highlights and step banners. "
            "Cannot be combined with --headless."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=browser["page_load_timeout"],
    )
    parser.add_argument(
        "--output",
        default=evidence["output_directory"],
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "Log more detail. Every run writes a log file to the logs/ "
            "directory; --verbose raises it to DEBUG level and also shows "
            "unreachable probes and errors on the console."
        ),
    )
    parser.add_argument(
        "--captcha",
        action="store_true",
        help=(
            "Pause the scan when a CAPTCHA is detected so you can solve it in "
            "the browser window, then press Enter to continue. Only pauses in "
            "visible mode with an interactive terminal; otherwise a detected "
            "CAPTCHA is recorded as a coverage gap and the scan continues. "
            "Off by default so runs never block unexpectedly."
        ),
    )
    parser.add_argument(
        "--allow-destructive",
        dest="allow_destructive",
        nargs="*",
        default=None,
        metavar="TERM",
        help=(
            "Let the workflow explorer activate controls normally skipped as "
            "destructive. Pass with no value to allow ALL of them, or list "
            "specific terms to allow only those (available: "
            f"{', '.join(destructive_terms)}). Only use this on systems you "
            "own or are explicitly authorized to test."
        ),
    )
    parser.add_argument(
        "--extra-selectors",
        dest="extra_selectors",
        nargs="+",
        metavar="CSS",
        help=(
            "Additional CSS selectors to inventory as controls, on top of the "
            "built-in inspection.control_selector. Useful for custom web "
            "components the default selector misses."
        ),
    )
    parser.add_argument(
        "--extra-selectors-file",
        dest="extra_selectors_file",
        help=(
            "Path to a file of extra CSS selectors, one per line (# comments "
            "and blank lines ignored). Loaded through the list provider and "
            "merged with any --extra-selectors."
        ),
    )

    auth = parser.add_argument_group(
        "authentication",
        "Test credentials for the checks that must reach a logged-in state.",
    )
    auth.add_argument("--username", help="Test account username.")
    auth.add_argument(
        "--password",
        help="Test account password. Falls back to the BANON_PASSWORD env var.",
    )
    auth.add_argument(
        "--login-url",
        dest="login_url",
        help="Explicit login page URL (otherwise the crawler's login page is used).",
    )
    auth.add_argument(
        "--secondary-username",
        help="Second test account username for cross-user access checks.",
    )
    auth.add_argument(
        "--secondary-password",
        help=(
            "Second test account password for cross-user access checks. "
            "Falls back to the BANON_SECONDARY_PASSWORD env var."
        ),
    )

    checks = parser.add_argument_group(
        "individual checks",
        "Run only the selected checks. Combine freely; omit to run all.",
    )
    for name, plugin in plugin_choices.items():
        checks.add_argument(
            f"--{name}",
            dest=f"select__{name}",
            action="store_true",
            help=plugin.DESCRIPTION,
        )

    parsed = parser.parse_args(args)

    if parsed.list_checks:
        _print_check_list(plugin_choices)
        raise SystemExit(0)

    selected = [
        name
        for name in plugin_choices
        if getattr(parsed, f"select__{name}", False)
    ]
    if parsed.scan:
        for name in parsed.scan:
            if name not in selected:
                selected.append(name)
    scan = selected or list(plugins["enabled"])

    allow_destructive, allow_destructive_terms = _resolve_destructive(
        parsed.allow_destructive,
        destructive_terms,
    )

    target = normalize_target(parsed.target) if parsed.target else None
    password = parsed.password or os.environ.get("BANON_PASSWORD")
    secondary_password = (
        parsed.secondary_password
        or os.environ.get("BANON_SECONDARY_PASSWORD")
    )
    login_url = normalize_target(parsed.login_url) if parsed.login_url else None

    settings = ScannerSettings(
        target=target,
        scan=scan,
        headless=False if parsed.watch else parsed.headless,
        watch=parsed.watch,
        timeout=parsed.timeout,
        output=parsed.output,
        defaults=defaults,
        project_root=PROJECT_ROOT,
        allow_destructive=allow_destructive,
        allow_destructive_terms=allow_destructive_terms,
        extra_selectors=list(parsed.extra_selectors or []),
        captcha_pause=parsed.captcha,
        verbose=parsed.verbose,
        username=parsed.username,
        password=password,
        login_url=login_url,
        secondary_username=parsed.secondary_username
        or os.environ.get("BANON_SECONDARY_USERNAME"),
        secondary_password=secondary_password,
    )

    if parsed.extra_selectors_file:
        try:
            selectors = ListProvider(settings).load(parsed.extra_selectors_file)
        except ValueError as exc:
            raise SystemExit(f"[ERROR] {exc}") from exc
        settings.extra_selectors.extend(selectors)

    return settings
