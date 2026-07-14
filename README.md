# Banon Web Scanner

Banon is an autonomous, Selenium-powered **QA security testing framework** for
authorized web application testing. It discovers application routes, inventories
each page at runtime, and applies every compatible drop-in plugin — without
page-specific selectors or page-object classes.

The framework is deterministic and contains no AI APIs, models, prompts, or
provider integrations. Only scan systems you own or have explicit permission to
test.

## Requirements

- Python 3.10+
- Google Chrome installed (the matching ChromeDriver is downloaded
  automatically by `webdriver-manager`)

## Install & run

You do **not** need to activate any virtualenv. Pick one of the following.

### Recommended for users — pipx (isolated, on PATH)

[pipx](https://pipx.pypa.io) installs the command into its own isolated
environment and puts just the `banon-web-scan` command on your PATH, so it works
from any directory without activating anything.

```bash
# one-time setup: install pipx and put its bin directory on your PATH
python -m pip install --user pipx
python -m pipx ensurepath          # then open a new terminal

# install Banon
pipx install git+https://github.com/banonhub/banon-web-scan.git

# now it works from anywhere
banon-web-scan --help
banon-web-scan --target https://authorized-target.example
```

`pipx ensurepath` is what makes the command available globally — a package
cannot add itself to your PATH, so pipx handles it (you only run it once). Later,
update with `pipx upgrade banon-web-scanner` or remove with
`pipx uninstall banon-web-scanner`.

### With pip

```bash
pip install git+https://github.com/banonhub/banon-web-scan.git
banon-web-scan --target https://authorized-target.example
```

Installing puts `banon-web-scan` (and the alias `banon-web-scanner`) on your
PATH. As long as the scripts directory of the Python you installed into is on
your PATH, no activation is required. (pipx is preferred because it also isolates
the dependencies from the rest of your system.)

### Editable install for development

```bash
pip install -e .        # or: pipx install -e .
banon-web-scan --target https://authorized-target.example
```

## Flags

```
banon-web-scan --target <url> [options]
```

| Flag | Meaning | Default |
| --- | --- | --- |
| `--target <url>` | Target origin to scan (required). A bare host is upgraded to `http://`. | — |
| `--scan <name...>` | Run these checks by name, or `all`. | `all` |
| `--headless` | Run Chrome hidden in headless mode. Cannot be combined with `--watch`. | visible |
| `--watch` | Open visible Chrome, slow browser actions, and highlight controls so you can follow the scan. Cannot be combined with `--headless`. | off |
| `--timeout <seconds>` | Page-load timeout. | `10` |
| `--output <dir>` | Report output directory (created in your working directory). | `reports` |
| `--captcha` | Pause when a CAPTCHA is detected so you can solve it in the browser, then press Enter to continue. Only pauses in visible mode with an interactive terminal; otherwise the CAPTCHA is recorded as a coverage gap and the scan continues. | off |
| `--verbose`, `-v` | Log more detail: raises the log file to DEBUG level and also shows unreachable probes and errors on the console. | off |

Every run also writes a log file to `logs/banon-scan-<timestamp>.log` (paired by
timestamp with the JSON and HTML reports), capturing the run timeline, findings,
and coverage gaps. Logging never aborts a scan — if the log file can't be
opened, the scan continues without one.

Each installed check also gets its own flag, so you can run just one:

```bash
banon-web-scan --target https://site --headers            # one check
banon-web-scan --target https://site --headers --https    # a few checks
banon-web-scan --target https://site --scan cookie_flags  # same, via --scan
```

## Route discovery

Banon starts from the target URL and discovers new pages by interacting with
visible navigation controls in the live browser, such as rendered links and
standalone buttons. It does not rely on bundled path wordlists,
related-subdomain guesses, robots/sitemaps, or background route harvesting.
Exploration is bounded and skips obvious destructive actions such as delete,
payment, logout, upload, save, and password-reset controls. On systems you own
you can lift that safety skip, either fully or selectively:

```bash
banon-web-scan --target https://site --allow-destructive              # allow all
banon-web-scan --target https://site --allow-destructive delete pay   # allow only these
```

Passing `--allow-destructive` with no value permits every destructive control;
passing one or more terms permits only those (the available terms are listed in
`--help`, and an unknown term is rejected with a clear error).

When a click opens a panel, drawer, or menu in place — the URL does not change
but the page's content-and-structure fingerprint does — Banon waits for the DOM
to settle, re-inventories the page, and follows any in-scope routes revealed
inside. This is bounded by `workflows.maximum_dynamic_panels` and can be turned
off with `workflows.explore_dynamic_panels` in `data/defaults.json`.

When credentials are provided and Banon reaches a real login form, it submits
that form through the browser and queues whichever same-origin page the
application lands on. The destination is learned from the browser transition,
not from hardcoded names like `/dashboard`.

## Built-in checks

| Flag | Check |
| --- | --- |
| `--page_health` | Blank pages, server errors (5xx), crash/error screens |
| `--console_errors` | Severe JavaScript console errors after load |
| `--headers` | Security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) |
| `--https` | Page uses HTTPS and HTTP redirects up to HTTPS |
| `--insecure_form_action` | Forms do not submit over cleartext HTTP (higher severity for password forms) |
| `--mixed_content` | HTTPS pages do not load scripts, iframes, or media over HTTP |
| `--info_headers` | Responses do not leak server/framework versions (Server, X-Powered-By, ...) |
| `--csp_strength` | A present CSP has no unsafe-inline/unsafe-eval, wildcards, or missing frame-ancestors/base-uri |
| `--url_secrets` | Session tokens, passwords, or API keys are not carried in URL query strings |
| `--cookie_flags` | Session/auth cookies have Secure, HttpOnly, SameSite |
| `--session_rotation` | Session cookie/token changes after login |
| `--logout_invalidation` | Protected pages cannot be accessed after logout |
| `--back_cache` | Sensitive data is not visible using browser Back after logout |
| `--protected_routes` | Protected URLs redirect or deny access when logged out |
| `--login_errors` | Failed login messages do not reveal whether an account exists |
| `--login_rate_limit` | Failed logins trigger delay, warning, CAPTCHA, or lockout |
| `--password_policy` | Weak passwords are rejected on signup/change-password pages |
| `--reset_enum` | Password reset responses stay generic for valid and invalid identities |
| `--csrf_presence` | State-changing forms include CSRF-like hidden tokens |
| `--csrf_uniqueness` | CSRF-like tokens are not reused statically across sessions |
| `--form_validation` | Invalid form submissions get clean validation messages |
| `--input_robustness` | Harmless special input does not crash pages |
| `--role_ui` | Normal users cannot see admin-only controls or links |
| `--cross_user_access` | A second user cannot access first-user resource URLs |
| `--browser_storage` | Browser storage does not contain secret-looking data |

`--cross_user_access` needs a second test account:

```bash
banon-web-scan --target https://site --username user1 --password pass1 \
  --secondary-username user2 --secondary-password pass2 --cross_user_access
```

## Drop-in plugins

Place a Python file in `plugins/` containing a `BasePlugin` subclass. No
registry edit is required — it is discovered automatically and gets its own
`--<name>` flag:

```python
from core.plugins import BasePlugin
from core.runtime import PluginResult


class ExamplePlugin(BasePlugin):
    NAME = "example"
    DESCRIPTION = "Checks compatible controls"

    def supports(self, inventory):
        return bool(inventory.forms)

    def scan(self, page, inventory):
        return PluginResult()
```

Plugins receive the live `ScanContext`, the generic browser toolkit, the list
provider, and the state detector. Applicability is decided per page from the
live inventory, so each page only runs the checks it can actually exercise.
`PluginResult` separates findings from authentication events and coverage
barriers. Page discovery is handled by the framework's safe button-click
workflow, not by plugins.

## Configuration

All tunable behavior is centralized in `data/defaults.json`: browser arguments,
crawl limits, scope, detection heuristics, workflow safeguards, per-plugin
settings, and evidence paths. Code reads required settings through
`ScannerSettings.get()` and fails clearly when a required setting is missing.

## License

Released under the [MIT License](LICENSE). Only scan systems you own or have
explicit permission to test.
