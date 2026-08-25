"""Run the restore inside the target container and read what it actually said.

The premise of Phase 0 is that `pg_restore`'s exit code is one bit and a
restore can fail in many more ways than that. Everything below was written
against measured output rather than recollection; the transcripts are pinned
in tests/test_firedrill.py.

What the measurements showed (PostgreSQL 16 and 18, custom format):

    healthy dump            exit 0, empty stderr
    role missing on target  exit 1, 'error: could not execute query: ERROR:
                            role "appuser" does not exist', then
                            'warning: errors ignored on restore: 1'
    truncated mid-data      exit 1, 'error: could not read from input file:
                            end of file'

Note this contradicts PLAN.md §3.3, which says these surface "as pg_restore
*warnings* with a zero exit code". For custom-format archives they do not --
the exit code was 1 in every broken case measured. The exit code is still not
sufficient, for two reasons that survive that correction:

  * It is one bit. It says something broke, never what, and "role absent" and
    "archive truncated" need different findings and different fixes.
  * A non-zero exit tells you nothing about severity. Treating every non-zero
    exit as a hard failure is how a tool starts crying wolf, and §8 is explicit
    that a false positive costs exactly what a false negative costs.

So firedrill uses both signals and says which one fired: stderr classifies,
the exit code is a backstop that guarantees an unrecognised failure can never
be read as success.
"""

from __future__ import annotations

import dataclasses
import re
import time

from .finding import Finding

# The database the archive is restored into. Named, not the default, so a
# restore that silently lands nowhere is visible.
TARGET_DB = "firedrill_restore"

# (pattern, rule, severity, fix). First match wins, so specific patterns come
# before the catch-alls at the bottom.
PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"could not read from input file|premature end|unexpected end of file",
                   re.I),
        "ARCHIVE_TRUNCATED", "critical",
        "The archive is incomplete. The backup job most likely ran out of disk or "
        "was killed. Check the writer's exit status and free space at write time -- "
        "pg_dump can exit 0 having written a short file.",
    ),
    (
        re.compile(r'role "([^"]+)" does not exist', re.I),
        "ROLE_ABSENT", "high",
        "Create the role on the restore target before restoring, or restore with "
        "--no-owner. Ownership silently defaulting to the restoring user changes "
        "who can read the data.",
    ),
    (
        re.compile(r'extension "([^"]+)" is not available|'
                   r"could not open extension control file|"
                   r'required extension "([^"]+)"', re.I),
        "EXTENSION_ABSENT", "high",
        "The extension's binaries are missing from the restore image. In a real "
        "recovery you would not have them either. Install it in the target image "
        "or the objects depending on it will not come back.",
    ),
    (
        re.compile(r"out of memory|no space left on device|disk full", re.I),
        "RESTORE_RESOURCE", "critical",
        "The restore target ran out of a resource. The result is incomplete "
        "regardless of what else this run reports.",
    ),
    (
        re.compile(r"could not execute query|could not create|could not connect", re.I),
        "RESTORE_ERROR", "high",
        "A statement in the archive failed to apply. The restored database is "
        "missing whatever that statement was creating.",
    ),
]

_ERROR_LINE = re.compile(r"^pg_restore:\s*(?:\[[^\]]*\]\s*)?error:\s*(.*)$", re.I)
_WARNING_LINE = re.compile(r"^pg_restore:\s*(?:\[[^\]]*\]\s*)?warning:\s*(.*)$", re.I)
_IGNORED_SUMMARY = re.compile(r"errors ignored on restore:\s*(\d+)", re.I)


@dataclasses.dataclass
class RestoreResult:
    exit_code: int
    seconds: float
    stderr: str
    errors_ignored: int
    findings: list[Finding]


def classify(line: str) -> tuple[str, str, str] | None:
    """(rule, severity, fix) for a message, or None if nothing matches."""
    for pattern, rule, severity, fix in PATTERNS:
        if pattern.search(line):
            return rule, severity, fix
    return None


def parse_stderr(stderr: str, exit_code: int) -> tuple[list[Finding], int]:
    """Turn pg_restore's stderr into findings. Pure -- no container needed.

    Kept free of subprocess calls on purpose: this is the logic most likely to
    break on a Postgres upgrade, and it is the part that has to be testable on
    a machine that cannot run Linux containers at all.
    """
    findings: list[Finding] = []
    errors_ignored = 0
    seen: set[tuple[str, str]] = set()

    for raw in (stderr or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        summary = _IGNORED_SUMMARY.search(line)
        if summary:
            errors_ignored = int(summary.group(1))
            continue

        error = _ERROR_LINE.match(line)
        warning = _WARNING_LINE.match(line)
        if not (error or warning):
            continue

        message = (error or warning).group(1).strip()
        hit = classify(message)
        if hit:
            rule, severity, fix = hit
        elif error:
            rule, severity, fix = (
                "RESTORE_ERROR", "high",
                "pg_restore reported an error firedrill does not recognise. Treated "
                "as a failure rather than ignored -- an unrecognised error is not a "
                "safe one.",
            )
        else:
            rule, severity, fix = (
                "RESTORE_WARNING", "medium",
                "pg_restore warned about something. Warnings here are findings, not "
                "noise; confirm the restored object set is what you expect.",
            )

        # One finding per distinct problem. A 40-table restore failing the same
        # way 40 times is one finding with the count, not 40 lines of report.
        key = (rule, message[:120])
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(stage="restore", rule=rule, severity=severity,
                    message=message, fix=fix, evidence=line)
        )

    # The backstop. A non-zero exit that produced nothing we could classify must
    # never come out looking like a clean run.
    if exit_code != 0 and not findings:
        findings.append(Finding(
            stage="restore", rule="RESTORE_FAILED", severity="critical",
            message=f"pg_restore exited {exit_code} without a message firedrill "
                    f"could classify.",
            fix="Read the captured stderr below. This is reported as a failure "
                "because an unexplained non-zero exit is not evidence of success.",
            evidence=(stderr or "").strip() or "(no stderr captured)",
        ))

    # And the inverse, which is the case PLAN.md §3.3 was reaching for: errors
    # present while the process claims success.
    if exit_code == 0 and (findings or errors_ignored):
        findings.append(Finding(
            stage="restore", rule="EXIT_CODE_LIED", severity="high",
            message=f"pg_restore exited 0 but reported {errors_ignored or len(findings)} "
                    f"problem(s) on stderr.",
            fix="Do not gate your backup pipeline on this exit code. This is the "
                "exact failure mode firedrill exists to catch.",
            evidence="",
        ))

    return findings, errors_ignored


def run_restore(container, jobs: int = 1, tier: str = "full") -> RestoreResult:
    """Restore the mounted archive inside the container, and time it.

    `tier` is "full" or "fast". A fast run passes --schema-only, which
    restores every object and no rows. That makes the row-reading rungs
    meaningless rather than passing, which drill.py handles by marking them
    NOT RUN -- see PLAN.md §3.5: a pass from a schema-only run must never look
    like a pass from a full one.
    """
    from .docker import DUMP_PATH

    created = container.exec(["createdb", "-U", "postgres", TARGET_DB], timeout=120)
    if created.returncode != 0:
        return RestoreResult(
            exit_code=created.returncode, seconds=0.0,
            stderr=created.stderr or "", errors_ignored=0,
            findings=[Finding(
                stage="restore", rule="TARGET_UNUSABLE", severity="critical",
                message=f"could not create the restore database {TARGET_DB}",
                fix="The container started but is not usable. This is reported as "
                    "a failure, not skipped.",
                evidence=(created.stderr or created.stdout or "").strip(),
            )],
        )

    argv = ["pg_restore", "-U", "postgres", "-d", TARGET_DB, "--no-password"]
    if tier == "fast":
        argv.append("--schema-only")
    if jobs > 1:
        argv += ["-j", str(jobs)]
    argv.append(DUMP_PATH)

    start = time.monotonic()
    result = container.exec(argv)
    seconds = time.monotonic() - start

    findings, errors_ignored = parse_stderr(result.stderr or "", result.returncode)
    return RestoreResult(
        exit_code=result.returncode, seconds=seconds,
        stderr=result.stderr or "", errors_ignored=errors_ignored,
        findings=findings,
    )


def smoke(container) -> tuple[list[Finding], dict]:
    """Prove the restored database answers questions, not just that a process exited.

    Counts only. Nothing here returns a row value -- see PLAN.md §7.
    """
    findings: list[Finding] = []

    alive = container.sql("select 1", database=TARGET_DB)
    if alive.returncode != 0 or alive.stdout.strip() != "1":
        findings.append(Finding(
            stage="smoke", rule="SMOKE_FAILED", severity="critical",
            message="the restored database did not answer `select 1`",
            fix="The restore reported one thing and the database another. Trust "
                "this result over the restore's exit code.",
            evidence=(alive.stderr or alive.stdout or "").strip(),
        ))
        return findings, {}

    counted = container.sql(
        "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace "
        "where c.relkind in ('r','p') and n.nspname not in "
        "('pg_catalog','information_schema')",
        database=TARGET_DB,
    )
    tables = int(counted.stdout.strip() or 0) if counted.returncode == 0 else -1

    if tables == 0:
        findings.append(Finding(
            stage="smoke", rule="EMPTY_RESTORE", severity="high",
            message="the restore completed but the database contains no user tables",
            fix="A dump of the wrong database, or of an empty one, restores "
                "perfectly. Check what the backup job was actually pointed at.",
            evidence="",
        ))
    elif tables < 0:
        findings.append(Finding(
            stage="smoke", rule="SMOKE_FAILED", severity="critical",
            message="could not count tables in the restored database",
            fix="The database accepted a connection but not a catalog query.",
            evidence=(counted.stderr or "").strip(),
        ))

    return findings, {"tables": tables}
