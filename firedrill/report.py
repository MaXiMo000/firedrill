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
    lines.append(f"  {_tier_note(report)}")
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
    if report.trend:
        # Context, not a finding. RTO is then a measured trend rather than a
        # claim, which is the whole reason history.json exists.
        lines.append(f"            {report.trend}")
    lines.append("")
    lines.append(f"  {_verdict(report)}")
    return "\n".join(lines)


def _tier_note(report: Report) -> str:
    """PLAN.md §3.5: say which tier ran, every time.

    A schema-only pass and a full pass are different claims about a backup,
    and a reader who cannot tell them apart has been misled by a green tick.
    """
    if report.tier == "fast":
        return ("tier: FAST -- schema only, no rows were restored. Row counts "
                "and smoke queries did NOT run.")
    return "tier: full"


def _verdict(report: Report) -> str:
    if not report.verified:
        # The distinction the whole tool is built on.
        return ("COULD NOT VERIFY -- the restore did not run, so this backup has "
                "not been proved to work.")
    if report.ok and report.tier == "fast":
        # Not the same claim as a full pass, so not the same sentence. This
        # run proved the schema comes back and nothing more.
        return ("PASS (fast tier) -- the schema restored. Whether the DATA is "
                "there was not checked.")
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


def as_junit(report: Report) -> str:
    """JUnit XML, so CI shows the rungs individually rather than one red X.

    The mapping matters more than the format. A stage that could not run is
    <skipped>, never a silent pass -- most CI dashboards colour skipped
    differently from passed, which is exactly the distinction this tool exists
    to preserve. A run that was never verified additionally carries a failing
    case of its own, so "could not verify" cannot be read as "nothing to
    report".
    """
    import xml.etree.ElementTree as ET

    by_stage: dict[str, list] = {}
    for finding in report.findings:
        by_stage.setdefault(finding.stage, []).append(finding)

    failures = sum(1 for s in report.stages if s.status == FAILED)
    skipped = sum(1 for s in report.stages
                  if s.status in (NOT_RUN, NOT_CONFIGURED))

    suite = ET.Element("testsuite", {
        "name": "firedrill",
        "tests": str(len(report.stages)),
        "failures": str(failures + (0 if report.verified else 1)),
        "skipped": str(skipped),
        "time": f"{report.total_seconds:.3f}",
    })
    suite.set("timestamp", _now())

    for stage in report.stages:
        case = ET.SubElement(suite, "testcase", {
            "classname": f"firedrill.{report.tier}",
            "name": stage.name,
            "time": f"{stage.seconds:.3f}",
        })
        if stage.status in (NOT_RUN, NOT_CONFIGURED):
            ET.SubElement(case, "skipped", {
                "message": f"{stage.status}: {stage.detail or 'no reason recorded'}"})
        elif stage.status == FAILED:
            found = by_stage.get(stage.name, ())
            failure = ET.SubElement(case, "failure", {
                "message": "; ".join(f.rule for f in found) or "failed",
                "type": "finding",
            })
            failure.text = "\n\n".join(
                f"{f.severity.upper()} {f.rule}\n{f.message}\n{f.fix}" for f in found)

    if not report.verified:
        case = ET.SubElement(suite, "testcase", {
            "classname": f"firedrill.{report.tier}", "name": "verified", "time": "0"})
        failure = ET.SubElement(case, "failure", {
            "message": "the restore could not be verified", "type": "unverified"})
        failure.text = ("This backup has NOT been proved to work. A verification "
                        "that could not run is not a pass.")

    return ET.tostring(suite, encoding="unicode") + "\n"


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def as_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)
