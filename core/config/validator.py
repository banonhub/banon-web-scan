from typing import Any


REQUIRED_TYPES: dict[tuple[str, ...], type | tuple[type, ...]] = {
    ("application", "command_name"): str,
    ("application", "reachability_paths"): list,
    ("browser", "page_load_timeout"): int,
    ("browser", "common_arguments"): list,
    ("browser", "watch"): dict,
    ("browser", "watch", "page_pause"): (int, float),
    ("browser", "watch", "plugin_pause"): (int, float),
    ("browser", "watch", "action_pause"): (int, float),
    ("browser", "watch", "highlight_duration"): (int, float),
    ("browser", "watch", "highlight_outline"): str,
    ("browser", "watch", "highlight_background"): str,
    ("browser", "watch", "scroll_block"): str,
    ("network", "http2"): bool,
    ("network", "verify_tls"): bool,
    ("network", "default_timeout"): (int, float),
    ("scope", "same_origin_only"): bool,
    ("scope", "allowed_schemes"): list,
    ("discovery", "maximum_pages"): int,
    ("discovery", "maximum_depth"): int,
    ("discovery", "probe_workers"): int,
    ("inspection", "control_selector"): str,
    ("inspection", "frame_selector"): str,
    ("inspection", "captcha_policy"): str,
    ("interaction", "ready_state"): list,
    ("authentication", "failed_attempts"): int,
    ("workflows", "activate_safe_controls"): bool,
    ("workflows", "explore_safe_forms"): bool,
    ("workflows", "explore_dynamic_panels"): bool,
    ("workflows", "navigational_control_types"): list,
    ("workflows", "blocked_control_terms"): list,
    ("plugins", "directory"): str,
    ("plugins", "enabled"): list,
    ("plugins", "aliases"): dict,
    ("plugins", "settings"): dict,
    ("evidence", "output_directory"): str,
    ("evidence", "report_filename"): str,
}

POSITIVE_NUMBERS = {
    ("application", "reachability_timeout"),
    ("browser", "page_load_timeout"),
    ("browser", "watch", "page_pause"),
    ("browser", "watch", "plugin_pause"),
    ("browser", "watch", "action_pause"),
    ("browser", "watch", "highlight_duration"),
    ("discovery", "maximum_pages"),
    ("discovery", "maximum_depth"),
    ("discovery", "probe_workers"),
    ("inspection", "maximum_frame_depth"),
    ("authentication", "failed_attempts"),
    ("workflows", "maximum_states"),
    ("workflows", "maximum_steps"),
    ("workflows", "maximum_dynamic_panels"),
}


def _read(document: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"Missing required setting: {'.'.join(path)}")
        value = value[key]
    return value


def validate_defaults(defaults: dict[str, Any]) -> None:
    """Fail at startup when the central defaults contract is incomplete."""
    errors: list[str] = []
    for path, expected in REQUIRED_TYPES.items():
        try:
            value = _read(defaults, path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(value, expected):
            errors.append(
                f"{'.'.join(path)} must be {expected}, "
                f"not {type(value).__name__}"
            )

    for path in POSITIVE_NUMBERS:
        try:
            value = _read(defaults, path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(value, (int, float)) or value <= 0:
            errors.append(f"{'.'.join(path)} must be a positive number")

    if errors:
        raise ValueError("Invalid defaults.json:\n- " + "\n- ".join(errors))
