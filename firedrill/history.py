"""The last-known-good record: durations, row counts, versions.

Two things become possible once runs are remembered, and neither can be done
from a single run:

* **RTO as a measured trend rather than a claim.** "Our restore got 40%
  slower this quarter" is invisible in any one report and obvious across
  twenty.
* **Row counts against the last known good.** `volume.tolerance` was refused
  until this file existed, because a tolerance needs something to be tolerant
  *of*.

What is deliberately NOT stored: anything from inside the database. Row counts
are aggregates, versions are catalog facts, durations are clock readings.
There is no field here that could hold a row, and the test asserting the
Finding field set has a sibling asserting this one -- a history file is the
most likely artefact of this tool to be committed to a repo by accident.
"""

from __future__ import annotations

import json
import pathlib
import time

# Enough to see a trend, small enough to stay readable and diffable in a repo.
# Old entries fall off the front rather than growing without bound, because a
# file nobody can open is a file nobody checks.
KEEP = 100


def _entry(report) -> dict:
    # Row counts come from the volume rung, which drill.py stashes on the
    # report. Absent when that rung did not run -- which is exactly when there
    # must be no numbers to mistake for a baseline later.
    counts = dict(getattr(report, "row_counts", {}) or {})

    return {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dump": report.dump,
        "tier": report.tier,
        "verified": report.verified,
        "ok": report.ok,
        "total_seconds": round(report.total_seconds, 3),
        "stages": {s.name: round(s.seconds, 3) for s in report.stages},
        "server_major": report.archive.get("restored_into_major"),
        "server_version": report.archive.get("server_version"),
        "size_bytes": report.archive.get("size_bytes"),
        "findings": sorted({f.rule for f in report.findings}),
        "row_counts": counts,
    }


def load(path: str | pathlib.Path) -> list[dict]:
    path = pathlib.Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A corrupt history is not a reason to fail a restore drill, but it is
        # also not something to silently overwrite -- see record().
        return []
    return data if isinstance(data, list) else []


def record(report, path: str | pathlib.Path) -> dict:
    """Append this run and return the entry written."""
    path = pathlib.Path(path)
    entries = load(path)
    entry = _entry(report)
    entries.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries[-KEEP:], indent=2) + "\n", encoding="utf-8")
    return entry


def last_good(entries: list[dict], tier: str = "full") -> dict | None:
    """The most recent run that actually passed, at the same tier.

    Tier matters: a fast run records no row counts and a sample run records
    only some, so comparing a full run against either would invent a loss.
    """
    for entry in reversed(entries):
        if entry.get("ok") and entry.get("verified") and entry.get("tier") == tier:
            return entry
    return None


def trend(entries: list[dict], current_seconds: float,
          tier: str = "full") -> str:
    """A one-line duration comparison, or '' when there is nothing to compare.

    Reported, never a finding. Inventing a threshold at which a restore is
    "too much slower" would produce a rule that fires on a noisy runner, and
    a DR tool that cries wolf gets muted. The explicit rto_budget is the
    finding; this is the context a human reads next to it.
    """
    previous = last_good(entries, tier)
    if not previous or not previous.get("total_seconds"):
        return ""
    before = previous["total_seconds"]
    change = (current_seconds - before) / before * 100.0
    direction = "slower" if change >= 0 else "faster"
    return (f"{abs(change):.0f}% {direction} than the last good {tier} run "
            f"({before:.1f}s on {previous.get('at', 'an earlier run')})")
