"""Human and JSON reporting.

The one thing the human reporter must never do is render an unverified run in
a way that resembles a pass. "NOT RUN" is printed for stages that did not
happen, and the verdict line says COULD NOT VERIFY rather than FAIL, because
those are different facts and conflating them is how people learn to ignore
the output.
"""

from __future__ import annotations

import json

from .drill import FAILED, NOT_RUN, OK, Report

_MARK = {OK: "ok  ", FAILED: "FAIL", NOT_RUN: "----"}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def human(report: Report, colour: bool = False) -> str:
    lines = []
    a = report.archive
    lines.append(f"firedrill  {report.dump}")
    if a:
        lines.append(
            f"  archive   {a.get('format')} v{a.get('archive_version')}  "
            f"{_size(a.get('size_bytes', 0))}  from {a.get('source_dbname')!r}"
        )
        lines.append(
            f"  source    PostgreSQL {a.get('server_version')}  "
            f"-> restored into postgres:{a.get('restored_into_major')}"
        )
    lines.append("")

    for stage in report.stages:
        detail = f"  {stage.detail}" if stage.detail else ""
        timing = f"{stage.seconds:6.2f}s" if stage.status != NOT_RUN else "     --"
        lines.append(f"  [{_MARK[stage.status]}] {stage.name:<9} {timing}{detail}")

    lines.append("")
    if report.findings:
        lines.append(f"  {len(report.findings)} finding(s):")
        for f in sorted(report.findings, key=lambda x: _SEVERITY_ORDER[x.severity]):
            lines.append(f"    {f.severity.upper():<8} {f.rule:<20} {f.message}")
            if f.fix:
                lines.append(f"             {_wrap(f.fix)}")
        lines.append("")

    lines.append(f"  total     {report.total_seconds:.2f}s"
                 + (f"  (budget {report.rto_budget:.0f}s)" if report.rto_budget else ""))
    lines.append("")
    lines.append(f"  {_verdict(report)}")
    return "\n".join(lines)


def _verdict(report: Report) -> str:
    if not report.verified:
        # The distinction the whole tool is built on.
        return ("COULD NOT VERIFY -- the restore did not run, so this backup has "
                "not been proved to work.")
    if report.ok:
        return "PASS -- restored and answered queries."
    return "FAIL -- the restore ran and produced findings above."


def _wrap(text: str, width: int = 66) -> str:
    import textwrap
    return ("\n" + " " * 13).join(textwrap.wrap(text, width))


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n}B"


def as_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)
