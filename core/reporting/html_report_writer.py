from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from core.config.settings import ScannerSettings


# Highest-to-lowest so findings and legends read in priority order.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class HtmlReportWriter:
    """Render the engine's result dict as a self-contained HTML report.

    The output is a single file with inline CSS and a small amount of vanilla
    JavaScript (severity filtering only) — no external assets, no network, and
    no third-party dependencies. It consumes exactly the same ``result`` dict
    the JSON report is built from, so the two stay in lock-step.
    """

    def __init__(self, settings: ScannerSettings):
        self.settings = settings

    def write(self, result: dict, *, timestamp: str | None = None) -> str:
        output = Path(self.settings.output).expanduser()
        directory = output if output.is_absolute() else Path.cwd() / output
        directory.mkdir(parents=True, exist_ok=True)
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        template = self.settings.get("evidence", "html_report_filename")
        path = directory / template.format(timestamp=timestamp)
        path.write_text(self.render(result), encoding="utf-8")
        return str(path)

    # -- rendering ---------------------------------------------------------
    def render(self, result: dict) -> str:
        findings = result.get("findings", [])
        counts = self._severity_counts(findings)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        json_name = Path(result["report"]).name if result.get("report") else ""

        return "\n".join(
            [
                "<!doctype html>",
                '<html lang="en">',
                "<head>",
                '<meta charset="utf-8">',
                '<meta name="viewport" content="width=device-width, '
                'initial-scale=1">',
                f"<title>Banon Web Scan — {escape(str(result.get('target', '')))}"
                "</title>",
                f"<style>{self._styles()}</style>",
                "</head>",
                "<body>",
                self._header(result, generated),
                '<main class="wrap">',
                self._summary(result, counts),
                self._severity_bar(counts),
                self._findings_section(findings, counts),
                self._routes_section(result.get("pages", [])),
                self._barriers_section(result.get("barriers", [])),
                "</main>",
                self._footer(json_name),
                f"<script>{self._script()}</script>",
                "</body>",
                "</html>",
                "",
            ]
        )

    # -- sections ----------------------------------------------------------
    def _header(self, result: dict, generated: str) -> str:
        target = escape(str(result.get("target", "")))
        authed = bool(result.get("authenticated"))
        badge_class = "badge badge-on" if authed else "badge badge-off"
        badge_text = "authenticated session" if authed else "anonymous session"
        return (
            '<header class="masthead">'
            '<div class="wrap">'
            '<div class="brand">Banon Web Scan</div>'
            f'<div class="target">{target}</div>'
            '<div class="meta">'
            f'<span class="{badge_class}">{badge_text}</span>'
            f'<span class="meta-item">Generated {escape(generated)}</span>'
            "</div>"
            "</div>"
            "</header>"
        )

    def _summary(self, result: dict, counts: dict) -> str:
        total = int(result.get("total_findings", len(result.get("findings", []))))
        scanned = int(result.get("pages_scanned", 0))
        discovered = int(result.get("pages_discovered", 0))
        gaps = len(result.get("barriers", []))
        actionable = sum(
            counts.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM")
        )
        cards = [
            self._stat_card(
                str(total),
                "Findings",
                f"{actionable} at medium+ severity",
                "accent" if total else "ok",
            ),
            self._stat_card(
                f"{scanned}",
                "Pages scanned",
                f"of {discovered} discovered",
                "neutral",
            ),
            self._stat_card(
                str(counts.get("CRITICAL", 0) + counts.get("HIGH", 0)),
                "High &amp; critical",
                "require attention" if actionable else "none reported",
                "danger"
                if (counts.get("CRITICAL", 0) + counts.get("HIGH", 0))
                else "ok",
            ),
            self._stat_card(
                str(gaps),
                "Coverage gaps",
                "checks blocked or skipped" if gaps else "none",
                "warn" if gaps else "ok",
            ),
        ]
        return f'<section class="stats">{"".join(cards)}</section>'

    def _stat_card(self, value: str, label: str, note: str, tone: str) -> str:
        return (
            f'<div class="card card-{tone}">'
            f'<div class="card-value">{value}</div>'
            f'<div class="card-label">{label}</div>'
            f'<div class="card-note">{note}</div>'
            "</div>"
        )

    def _severity_bar(self, counts: dict) -> str:
        total = sum(counts.values())
        if not total:
            return ""
        segments = []
        legend = []
        for level in SEVERITY_ORDER:
            count = counts.get(level, 0)
            if not count:
                continue
            pct = count / total * 100
            segments.append(
                f'<span class="seg sev-{level.lower()}" '
                f'style="width:{pct:.4f}%" title="{level}: {count}"></span>'
            )
            legend.append(
                f'<span class="legend-item">'
                f'<span class="dot sev-{level.lower()}"></span>'
                f"{level.title()} <strong>{count}</strong></span>"
            )
        return (
            '<section class="sev-breakdown">'
            '<h2>Severity breakdown</h2>'
            f'<div class="bar">{"".join(segments)}</div>'
            f'<div class="legend">{"".join(legend)}</div>'
            "</section>"
        )

    def _findings_section(self, findings: list, counts: dict) -> str:
        if not findings:
            return (
                '<section class="findings">'
                "<h2>Findings</h2>"
                '<div class="empty ok-panel">'
                "No findings were reported for this scan."
                "</div>"
                "</section>"
            )

        ordered = sorted(
            findings,
            key=lambda finding: (
                self._severity_rank(finding.get("severity", "INFO")),
                str(finding.get("plugin", "")),
                str(finding.get("title", "")),
            ),
        )
        filters = [
            f'<button class="filter is-active" data-severity="all">'
            f"All <span>{len(findings)}</span></button>"
        ]
        for level in SEVERITY_ORDER:
            count = counts.get(level, 0)
            if not count:
                continue
            filters.append(
                f'<button class="filter" data-severity="{level.lower()}">'
                f"{level.title()} <span>{count}</span></button>"
            )
        cards = "".join(self._finding_card(finding) for finding in ordered)
        return (
            '<section class="findings">'
            '<div class="findings-head">'
            "<h2>Findings</h2>"
            f'<div class="filters">{"".join(filters)}</div>'
            "</div>"
            f'<div class="finding-list">{cards}</div>'
            "</section>"
        )

    def _finding_card(self, finding: dict) -> str:
        severity = str(finding.get("severity", "INFO")).upper()
        sev_class = severity.lower()
        title = escape(str(finding.get("title", "Untitled finding")))
        description = escape(str(finding.get("description", "")))
        plugin = escape(str(finding.get("plugin", "unknown")))
        timestamp = escape(str(finding.get("timestamp", "")))
        evidence = finding.get("evidence") or {}
        url = evidence.get("url") if isinstance(evidence, dict) else None
        meta = [f'<span class="chip">{plugin}</span>']
        if url:
            meta.append(f'<span class="finding-url">{escape(str(url))}</span>')
        if timestamp:
            meta.append(f'<span class="finding-time">{timestamp}</span>')
        evidence_block = ""
        if evidence:
            pretty = escape(
                json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True)
            )
            evidence_block = (
                "<details class=\"evidence\">"
                "<summary>Evidence</summary>"
                f"<pre>{pretty}</pre>"
                "</details>"
            )
        return (
            f'<article class="finding" data-severity="{sev_class}">'
            f'<div class="finding-top">'
            f'<span class="pill sev-{sev_class}">{escape(severity)}</span>'
            f'<h3 class="finding-title">{title}</h3>'
            "</div>"
            f'<div class="finding-meta">{"".join(meta)}</div>'
            f'<p class="finding-desc">{description}</p>'
            f"{evidence_block}"
            "</article>"
        )

    def _routes_section(self, pages: list) -> str:
        if not pages:
            return ""
        rows = []
        for page in pages:
            path = escape(str(page.get("path", page.get("url", ""))))
            page_type = escape(str(page.get("page_type", "")))
            status = page.get("status_code")
            status_text = escape(str(status)) if status is not None else "—"
            authed = "yes" if page.get("authenticated") else "no"
            scanned = "yes" if page.get("scanned") else "no"
            rows.append(
                "<tr>"
                f'<td class="mono">{path}</td>'
                f"<td>{page_type}</td>"
                f'<td class="num">{status_text}</td>'
                f'<td class="center">{authed}</td>'
                f'<td class="center">{scanned}</td>'
                "</tr>"
            )
        return (
            '<section class="routes">'
            f"<h2>Discovered routes <span class=\"count\">{len(pages)}</span></h2>"
            '<div class="table-scroll">'
            "<table>"
            "<thead><tr>"
            "<th>Path</th><th>Type</th><th>Status</th>"
            "<th>Auth</th><th>Scanned</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</div>"
            "</section>"
        )

    def _barriers_section(self, barriers: list) -> str:
        if not barriers:
            return ""
        rows = []
        for barrier in barriers:
            kind = escape(str(barrier.get("kind", "")))
            url = escape(str(barrier.get("url", "")))
            detail = escape(str(barrier.get("detail", "")))
            rows.append(
                "<tr>"
                f'<td class="chip-cell"><span class="chip">{kind}</span></td>'
                f'<td class="mono">{url}</td>'
                f"<td>{detail}</td>"
                "</tr>"
            )
        return (
            '<section class="barriers">'
            "<h2>Coverage gaps "
            f'<span class="count">{len(barriers)}</span></h2>'
            '<p class="section-note">'
            "Checks that could not fully run — blocked pages, failed "
            "navigation, captcha, or plugin errors."
            "</p>"
            '<div class="table-scroll">'
            "<table>"
            "<thead><tr><th>Kind</th><th>URL</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</div>"
            "</section>"
        )

    def _footer(self, json_name: str) -> str:
        json_note = (
            f'<span class="meta-item">Machine-readable JSON: '
            f'<span class="mono">{escape(json_name)}</span></span>'
            if json_name
            else ""
        )
        return (
            '<footer class="foot">'
            '<div class="wrap">'
            "<span>Generated by Banon Web Scanner — authorized QA security "
            "testing only.</span>"
            f"{json_note}"
            "</div>"
            "</footer>"
        )

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _severity_rank(severity: str) -> int:
        try:
            return SEVERITY_ORDER.index(str(severity).upper())
        except ValueError:
            return len(SEVERITY_ORDER)

    @staticmethod
    def _severity_counts(findings: list) -> dict:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in findings:
            level = str(finding.get("severity", "INFO")).upper()
            if level in counts:
                counts[level] += 1
            else:
                counts.setdefault(level, 0)
                counts[level] += 1
        return counts

    @staticmethod
    def _styles() -> str:
        return """
        :root{
          --bg:#f5f7fa; --panel:#ffffff; --ink:#12202f; --muted:#5a6b7b;
          --line:#e2e8f0; --shadow:0 1px 3px rgba(15,32,47,.08),0 8px 24px rgba(15,32,47,.06);
          --accent:#2563eb;
          --critical:#7f1d1d; --high:#dc2626; --medium:#d97706;
          --low:#2563eb; --info:#0891b2;
        }
        @media (prefers-color-scheme:dark){
          :root{
            --bg:#0b1622; --panel:#111f2e; --ink:#e8f0f7; --muted:#93a5b6;
            --line:#22344a; --shadow:0 1px 3px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.35);
            --accent:#60a5fa;
            --critical:#f87171; --high:#f26d6d; --medium:#fbbf24;
            --low:#60a5fa; --info:#22d3ee;
          }
        }
        *{box-sizing:border-box}
        html{-webkit-text-size-adjust:100%}
        body{
          margin:0; background:var(--bg); color:var(--ink);
          font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
        }
        .wrap{max-width:1080px;margin:0 auto;padding:0 24px}
        h2{font-size:18px;margin:0 0 16px;letter-spacing:.01em}
        h3{margin:0}
        .masthead{
          background:linear-gradient(135deg,#0b2138,#0f2e4d);
          color:#eaf3fb;padding:34px 0 30px;border-bottom:1px solid rgba(255,255,255,.06);
        }
        .brand{font-size:13px;letter-spacing:.16em;text-transform:uppercase;opacity:.8}
        .target{font-size:26px;font-weight:650;margin:6px 0 14px;word-break:break-all}
        .meta{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;font-size:13px}
        .meta-item{color:#b9cee0}
        .badge{padding:3px 11px;border-radius:999px;font-size:12px;font-weight:600}
        .badge-on{background:rgba(34,197,94,.18);color:#8ff0b4;border:1px solid rgba(34,197,94,.4)}
        .badge-off{background:rgba(148,163,184,.16);color:#c7d5e2;border:1px solid rgba(148,163,184,.35)}
        section{margin:30px 0}
        .stats{
          display:grid;gap:16px;margin-top:-26px;
          grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
        }
        .card{
          background:var(--panel);border:1px solid var(--line);border-radius:12px;
          padding:18px 20px;box-shadow:var(--shadow);
        }
        .card-value{font-size:32px;font-weight:700;line-height:1}
        .card-label{margin-top:8px;font-weight:600}
        .card-note{color:var(--muted);font-size:12.5px;margin-top:2px}
        .card-danger .card-value{color:var(--high)}
        .card-warn .card-value{color:var(--medium)}
        .card-ok .card-value{color:#16a34a}
        .card-accent .card-value{color:var(--accent)}
        .bar{display:flex;height:16px;border-radius:8px;overflow:hidden;background:var(--line)}
        .seg{display:block;height:100%}
        .legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:12px;font-size:13px}
        .legend-item{display:flex;align-items:center;gap:7px;color:var(--muted)}
        .legend-item strong{color:var(--ink)}
        .dot{width:11px;height:11px;border-radius:3px;display:inline-block}
        .sev-critical{background:var(--critical)}
        .sev-high{background:var(--high)}
        .sev-medium{background:var(--medium)}
        .sev-low{background:var(--low)}
        .sev-info{background:var(--info)}
        .findings-head{display:flex;flex-wrap:wrap;gap:14px;justify-content:space-between;align-items:center;margin-bottom:16px}
        .findings-head h2{margin:0}
        .filters{display:flex;flex-wrap:wrap;gap:8px}
        .filter{
          cursor:pointer;border:1px solid var(--line);background:var(--panel);
          color:var(--muted);border-radius:999px;padding:5px 13px;font:inherit;
          font-size:13px;font-weight:600;transition:.15s;
        }
        .filter span{opacity:.7;margin-left:4px}
        .filter:hover{color:var(--ink)}
        .filter.is-active{background:var(--accent);border-color:var(--accent);color:#fff}
        .filter.is-active span{opacity:.85}
        .finding-list{display:flex;flex-direction:column;gap:14px}
        .finding{
          background:var(--panel);border:1px solid var(--line);border-radius:12px;
          padding:18px 20px;box-shadow:var(--shadow);border-left:4px solid var(--line);
        }
        .finding[data-severity=critical]{border-left-color:var(--critical)}
        .finding[data-severity=high]{border-left-color:var(--high)}
        .finding[data-severity=medium]{border-left-color:var(--medium)}
        .finding[data-severity=low]{border-left-color:var(--low)}
        .finding[data-severity=info]{border-left-color:var(--info)}
        .finding-top{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
        .finding-title{font-size:16px}
        .pill{
          font-size:11px;font-weight:700;letter-spacing:.05em;color:#fff;
          padding:3px 9px;border-radius:6px;flex:none;
        }
        .pill.sev-info{color:#04252c}
        .pill.sev-medium{color:#3a2503}
        .finding-meta{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin:10px 0;font-size:12.5px;color:var(--muted)}
        .chip{background:var(--line);color:var(--ink);border-radius:6px;padding:2px 8px;font-weight:600;font-size:12px}
        .finding-url{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;word-break:break-all}
        .finding-desc{margin:6px 0 0}
        .evidence{margin-top:12px}
        .evidence summary{cursor:pointer;font-size:13px;font-weight:600;color:var(--accent)}
        .evidence pre{
          margin:10px 0 0;padding:14px;background:var(--bg);border:1px solid var(--line);
          border-radius:8px;overflow-x:auto;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace;
        }
        .empty,.ok-panel{
          background:var(--panel);border:1px solid var(--line);border-radius:12px;
          padding:20px;color:var(--muted);box-shadow:var(--shadow);
        }
        .ok-panel{border-left:4px solid #16a34a}
        .count{
          display:inline-block;font-size:13px;font-weight:600;color:var(--muted);
          background:var(--line);border-radius:999px;padding:1px 10px;vertical-align:middle;
        }
        .section-note{color:var(--muted);font-size:13.5px;margin:-8px 0 14px}
        .table-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
        table{width:100%;border-collapse:collapse;background:var(--panel);font-size:13.5px}
        th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
        th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
        tbody tr:last-child td{border-bottom:none}
        .mono{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
        .num,.center{text-align:center;white-space:nowrap}
        .foot{border-top:1px solid var(--line);margin-top:40px;padding:22px 0;color:var(--muted);font-size:12.5px}
        .foot .wrap{display:flex;flex-wrap:wrap;gap:6px 20px;justify-content:space-between}
        """

    @staticmethod
    def _script() -> str:
        return """
        (function(){
          var filters=document.querySelectorAll('.filter');
          var findings=document.querySelectorAll('.finding');
          filters.forEach(function(btn){
            btn.addEventListener('click',function(){
              filters.forEach(function(b){b.classList.remove('is-active')});
              btn.classList.add('is-active');
              var want=btn.getAttribute('data-severity');
              findings.forEach(function(card){
                var show=want==='all'||card.getAttribute('data-severity')===want;
                card.style.display=show?'':'none';
              });
            });
          });
        })();
        """
