"""Point-in-time recovery: the check nobody does.

A dump proves you can get *a* database back. PITR proves you can get it back to
a *chosen moment* — which is the thing you actually need after someone runs a
DELETE without a WHERE clause at 14:02. Almost nobody tests it, because testing
it means performing it.

The assertion that makes this worth anything has two halves, and either half
alone is satisfiable by a broken restore:

* a row written **before** the target exists  — restoring everything passes this
* a row written **after** the target does not  — restoring nothing passes this

Only together do they say recovery stopped where it was told to. Both are
expressed as ordinary `semantics:` checks, so this module contributes a
recovered database and the existing ladder does the asking.

Measured on PostgreSQL 16, which shaped the design:

* An unreachable target does **not** silently promote. The startup process
  exits with `FATAL: recovery ended before configured recovery target was
  reached` and the container stops. That is the loud failure we want, and it
  means "did recovery reach its target" needs no heuristic — a server that is
  up is a server that stopped where it was asked.
* The official image only runs `initdb` when PGDATA is empty, so a base backup
  copied in is *started* rather than initialised. The copy lands as root and
  Postgres refuses a group-readable data directory, hence the chown and the
  chmod 700 in the seed script.
"""

from __future__ import annotations

import pathlib
import re

from . import archive, docker
from .finding import Finding

# The startup process says exactly this when the WAL runs out before the
# target. Pinned as a string because it is the difference between "recovered to
# 14:01" and "recovered to whenever the archive happened to end".
_TARGET_UNREACHED = "recovery ended before configured recovery target was reached"

# Seeds PGDATA from the mounted base backup and hands over to the image's own
# entrypoint, which then starts a server that recovers rather than initialises.
_SEED = """
set -e
cp -a /seed/. "$PGDATA"/
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
touch "$PGDATA/recovery.signal"
cat >> "$PGDATA/postgresql.conf" <<'FIREDRILL'
restore_command = 'cp /wal/%f %p'
recovery_target_time = '{target}'
recovery_target_action = 'promote'
FIREDRILL
exec docker-entrypoint.sh postgres
"""


def major_of_base(base: pathlib.Path) -> str:
    """The major version, read out of the base backup's own PG_VERSION.

    Same principle as reading it from a dump header: ask the artefact what it
    is rather than the host what it happens to have.
    """
    marker = pathlib.Path(base) / "PG_VERSION"
    try:
        text = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise archive.ArchiveError(
            f"{base} does not look like a base backup: no readable PG_VERSION "
            f"({exc})"
        ) from None
    if not re.fullmatch(r"\d+(\.\d+)?", text):
        raise archive.ArchiveError(f"PG_VERSION says {text!r}, which is not a version")
    return text


class RecoveryContainer(docker.Container):
    """A container that recovers a base backup to a timestamp, then promotes."""

    def __init__(self, major: str, base: pathlib.Path, wal: pathlib.Path,
                 target: str, **kw):
        super().__init__(major, **kw)
        self.base = pathlib.Path(base).resolve()
        self.wal = pathlib.Path(wal).resolve()
        self.target = target

    def _run_argv(self) -> list[str]:
        # Mounted read-only, like the dump: "never writes to the source" stays a
        # property of the mount rather than a promise about our own code.
        return [
            "docker", "run", "-d", "--name", self.name,
            "--label", "firedrill=1",
            # By name, never by value: /proc/*/cmdline is world-readable.
            "-e", "POSTGRES_PASSWORD",
            "-v", f"{self.base}:/seed:ro",
            "-v", f"{self.wal}:/wal:ro",
            "--entrypoint", "bash",
            self.image,
            "-c", _SEED.format(target=self.target),
        ]


def recover(base, wal, target: str, *, flavour: str = "",
            ready_timeout: int = docker.DEFAULT_READY_TIMEOUT):
    """Bring up a database recovered to `target`.

    Returns (container, findings). When findings are non-empty the container is
    already torn down and there is nothing to query -- recovery did not reach
    the point it was asked for, so anything measured on it would describe a
    different moment than the one under test.
    """
    base, wal = pathlib.Path(base), pathlib.Path(wal)
    major = major_of_base(base)
    container = RecoveryContainer(major, base, wal, target, flavour=flavour,
                                  ready_timeout=ready_timeout)
    try:
        container.start()
        container.wait_ready()
    except docker.TargetError as exc:
        logs = container.logs(tail=200)
        container.teardown()
        if _TARGET_UNREACHED in logs:
            return None, [Finding(
                stage="recover", rule="PITR_TARGET_UNREACHED", severity="critical",
                message=f"recovery could not reach {target}: the WAL archive ends "
                        "before it",
                fix="The base backup and the WAL you have cannot reconstruct that "
                    "moment. Either segments are missing from the archive, or the "
                    "target is later than anything that was archived. This is the "
                    "failure you would meet during the incident, discovered now.",
                # Where it actually stopped, which is the first thing anyone
                # asks and the last thing a bare "unreached" tells them.
                evidence=_recovery_trace(logs),
            )]
        return None, [Finding(
            stage="recover", rule="PITR_FAILED", severity="critical",
            message=f"the recovery could NOT be verified: {exc}",
            fix="The server never came up, so nothing about this base backup or "
                "its WAL has been proved.",
            evidence=_last_error(logs),
        )]

    return container, []


def confirm_promoted(container) -> list[Finding]:
    """It is out of recovery, so it stopped where it was told to.

    Cheap, and worth asserting rather than assuming: a server still in recovery
    would answer queries as a read-only replica and every downstream check would
    pass against a database that never finished arriving.
    """
    answer = container.sql("select pg_is_in_recovery()")
    if answer.returncode != 0:
        return [Finding(
            stage="recover", rule="PITR_FAILED", severity="critical",
            message="the recovered server would not answer whether it is still "
                    "in recovery",
            fix="Treat this as unrecovered. A database that cannot describe its "
                "own state has not been verified.",
            evidence=(answer.stderr or "").strip(),
        )]
    if answer.stdout.strip() != "f":
        return [Finding(
            stage="recover", rule="PITR_STILL_IN_RECOVERY", severity="critical",
            message="the server is still in recovery, so it never reached the "
                    "target and promoted",
            fix="Every check after this one would run against a database that is "
                "still arriving, and would pass. Reported instead.",
            evidence="",
        )]
    return []


# The lines that say how far recovery got. Postgres reports the last completed
# transaction time and any restore_command failures, which together distinguish
# "the archive is short" from "the archive is unreadable".
_TRACE = re.compile(
    r"(last completed transaction|redo done|recovery stopping|restored log file|"
    r"could not|invalid|FATAL|starting point-in-time recovery|consistent recovery)",
    re.I)


def _recovery_trace(logs: str, keep: int = 12) -> str:
    lines = [l.strip() for l in logs.splitlines() if _TRACE.search(l)]
    return "\n".join(lines[-keep:]) if lines else logs.strip()[-600:]


def _last_error(logs: str) -> str:
    for line in reversed(logs.splitlines()):
        if "FATAL" in line or "PANIC" in line:
            return line.strip()
    return logs.strip()[-500:]
