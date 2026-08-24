"""Human and JSON reporting.

The one thing the human reporter must never do is render an unverified run in
a way that resembles a pass. "NOT RUN" is printed for stages that did not
happen, and the verdict line says COULD NOT VERIFY rather than FAIL, because
those are different facts and conflating them is how people learn to ignore
the output.
"""

from __future__ import annotations

import json

from .drill import FAILED, NOT_CONFIGURED, NOT_RUN, OK, Report

_MARK = {OK: "ok  ", FAILED: "FAIL", NOT_RUN: "----", NOT_CONFIGURED: "n/a "}

# A status with no mark must not take the reporter down with it: the report is
# how every other failure gets communicated, so it is the last thing that
# should crash. An unknown status renders as '????' and stays visible.
_UNKNOWN_MARK = "????"

# Neither of these ran, so neither gets a duration that implies it did.
_NO_TIMING = (NOT_RUN, NOT_CONFIGURED)

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
        timing = "     --" if stage.status in _NO_TIMING else f"{stage.seconds:6.2f}s"
        mark = _MARK.get(stage.status, _UNKNOWN_MARK)
        lines.append(f"  [{mark}] {stage.name:<9} {timing}{detail}")

    lines.append("")
    if report.findings:
        lines.append(f"  {len(report.findings)} finding(s):")
        for f in sorted(report.findings, key=lambda x: _SEVERITY_ORDER[x.severity]):
            lines.append(f"    {f.severity.upper():<8} {f.rule:<20} {f.message}")
            if f.fix:
                lines.append(f"             {_wrap(f.fix)}")
        lines.append("")

    if report.suppressed:
        # Suppressed is not deleted. PLAN.md §6 requires a written reason for
        # every ignore, and the report prints it, so a green run always shows
        # what was set aside to make it green.
        lines.append(f"  {len(report.suppressed)} suppressed by config:")
        for item in report.suppressed:
            lines.append(f"    {item['rule']:<20} {item['reason']}")
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
