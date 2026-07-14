from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from core.config.settings import ScannerSettings


class ScopePolicy:
    """Normalize candidates and enforce configured crawl boundaries."""

    def __init__(self, target: str, settings: ScannerSettings):
        self.target = target.rstrip("/")
        self.settings = settings
        self.origin = urlsplit(self.target)

    def normalize(self, candidate: str, current_url: str | None = None) -> str | None:
        if not candidate:
            return None
        absolute = urljoin(current_url or self.target, candidate)
        parts = urlsplit(absolute)
        scope = self.settings.get("scope")

        if parts.scheme.lower() not in scope["allowed_schemes"]:
            return None
        same_origin = (
            parts.scheme.lower() == self.origin.scheme.lower()
            and parts.netloc.lower() == self.origin.netloc.lower()
        )
        if scope["same_origin_only"] and not same_origin:
            return None

        path = parts.path or "/"
        lowered = path.lower()
        if any(marker.lower() in lowered for marker in scope["excluded_paths"]):
            return None
        if any(
            lowered.endswith(extension.lower())
            for extension in scope["excluded_extensions"]
        ):
            return None

        query = parts.query
        if scope["query_policy"] == "drop":
            query = ""
        elif scope["query_policy"] == "sort":
            query = urlencode(sorted(parse_qsl(query, keep_blank_values=True)))

        fragment = parts.fragment if scope["include_fragments"] else ""
        # Collapse the site root to the bare origin (no trailing slash) so it
        # matches the normalized target and is never queued twice.
        return urlunsplit(
            (
                parts.scheme.lower(),
                parts.netloc.lower(),
                path.rstrip("/"),
                query,
                fragment,
            )
        )

    def is_allowed(self, candidate: str, current_url: str | None = None) -> bool:
        return self.normalize(candidate, current_url) is not None
