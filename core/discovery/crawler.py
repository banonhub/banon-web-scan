from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

from core.config.settings import ScannerSettings
from core.discovery.scope_policy import ScopePolicy
from core.net import build_client, request_error
from core.runtime.entities import PageRecord


ProbeProgress = Callable[
    [PageRecord, bool, int | None, str | None],
    None,
]


class DiscoveryEngine:
    """Learn routes from the application instead of relying on fixed URL names."""

    def __init__(
        self,
        target: str,
        settings: ScannerSettings,
    ):
        self.target = target.rstrip("/")
        self.settings = settings
        self.scope = ScopePolicy(self.target, settings)

    def initial_pages(self) -> list[PageRecord]:
        return self._records([self.target], source="initial", depth=0)

    def probe_pages(
        self,
        pages: list[PageRecord],
        *,
        progress: ProbeProgress | None = None,
    ) -> list[PageRecord]:
        """Keep only paths that return a configured reachable HTTP status."""
        discovery = self.settings.get("discovery")
        reachable = set(discovery["reachable_status_codes"])
        timeout = float(discovery["probe_timeout"])
        workers = min(
            max(int(discovery["probe_workers"]), 1),
            max(len(pages), 1),
        )
        client = build_client(
            self.settings,
            timeout=timeout,
            follow_redirects=True,
        )

        def probe(page: PageRecord):
            try:
                response = client.get(page.url)
            except request_error as exc:
                return page, None, str(exc)
            return page, response, None

        ordered: list[tuple[int, PageRecord]] = []
        try:
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="banon-probe",
            ) as pool:
                pending = {
                    pool.submit(probe, page): index
                    for index, page in enumerate(pages)
                }
                for future in as_completed(pending):
                    index = pending[future]
                    page, response, error = future.result()
                    status_code = (
                        response.status_code
                        if response is not None
                        else None
                    )
                    is_reachable = bool(
                        response is not None
                        and status_code in reachable
                    )
                    if progress is not None:
                        progress(
                            page,
                            is_reachable,
                            status_code,
                            error,
                        )
                    if not is_reachable:
                        continue
                    page.status_code = response.status_code
                    page.final_url = str(response.url)
                    page.status = "discovered"
                    ordered.append((index, page))
        finally:
            client.close()
        return [
            page
            for _, page in sorted(ordered, key=lambda item: item[0])
        ]

    def _records(
        self,
        candidates: list[str],
        *,
        source: str,
        depth: int,
        authenticated: bool = False,
        current_url: str | None = None,
    ) -> list[PageRecord]:
        records: list[PageRecord] = []
        seen: set[str] = set()
        for candidate in candidates:
            normalized = self.scope.normalize(candidate, current_url)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            parts = urlsplit(normalized)
            target_parts = urlsplit(self.target)
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
            if parts.fragment:
                path = f"{path}#{parts.fragment}"
            if parts.netloc.lower() != target_parts.netloc.lower():
                path = f"//{parts.netloc}{path}"
            records.append(
                PageRecord(
                    url=normalized,
                    path=path,
                    source=source,
                    authenticated=authenticated,
                    depth=depth,
                )
            )
        return records
