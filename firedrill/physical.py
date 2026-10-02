"""Physical backups: pgBackRest and WAL-G.

Most production Postgres is not backed up with pg_dump. It is backed up
with pgBackRest or WAL-G -- a base backup plus a WAL archive -- and those are
restored with the tool itself, into a data directory, followed by WAL
replay. This module does exactly that, into a disposable container of the
backup's own major version, and hands the recovered server to the same
ladder every other drill uses.

Safety, because a physical restore carries production's own configuration:

* **archive_mode is forced off.** A restored data directory keeps the
  source's postgresql.conf, and production's `archive_command` pushes WAL
  into production's backup repository. Started as-is, the drill would write
  into the very archive it is checking. `-c archive_mode=off` on the server's
  command line outranks every file.
* A local repository is mounted read-only. A remote one (S3, GCS, Azure) is
  reached with credentials passed to the container by *name*, never value.
* Nothing is published: no port, same as every other target.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess

from . import docker
from .finding import Finding

TOOLS = ("pgbackrest", "walg")

# WAL-G has no distro package, so its release binary is fetched at image
# build time and checked against the digest published with the release.
WALG_VERSION = "v3.0.9"
WALG_URL = f"https://github.com/wal-g/wal-g/releases/download/{WALG_VERSION}/wal-g-pg-22.04-amd64"
WALG_SHA256 = "d6795c663894d836ba20840bffe8970aed81bbe25d3151bd4951f6f9c362def9"

# Environment the tools read their repository settings and cloud
# credentials from. Passed through by name only.
_PASS_THROUGH = ("PGBACKREST_", "WALG_", "WALE_", "AWS_", "GOOGLE_", "AZURE_", "GCS_")

REPO_MOUNT = "/firedrill/repo"

_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class PhysicalError(Exception):
    """The backup could not be located or read before anything started."""


class TargetBeforeBackup(PhysicalError):
    """No backup finished at or before the recovery target. Postgres cannot
    stop recovery before a backup's end: asked to, it either refuses or --
    when nothing committed during the backup -- quietly recovers to a LATER
    moment than the one asked for. Decided here, from the repository."""


def parse_target(target: str) -> dt.datetime:
    """A validated target as an aware datetime; no offset means UTC, which
    is the restore container's zone."""
    text = target.strip().replace(" ", "T", 1)
    if re.search(r"[+-]\d\d$", text):
        text += ":00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = dt.datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


# -- reading the repository ------------------------------------------------

def _ini_section(text: str, section: str) -> dict[str, str]:
    out, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
        elif current == section and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def pgbackrest_backup(repo: pathlib.Path, stanza: str | None, before=None) -> dict:
    """{stanza, major, label, finished} for the newest backup, read from the
    repository's own backup.info -- the same principle as reading a dump
    header: ask the artefact, not the host."""
    stanzas = sorted(p.name for p in (repo / "backup").glob("*") if (p / "backup.info").exists())
    if stanza is None:
        if len(stanzas) != 1:
            raise PhysicalError(
                f"{repo} holds {len(stanzas)} stanzas ({', '.join(stanzas) or 'none'}); "
                "name one with --stanza")
        stanza = stanzas[0]
    info_path = repo / "backup" / stanza / "backup.info"
    try:
        text = info_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PhysicalError(f"no readable backup.info for stanza {stanza!r}: {exc}") from None
    major = _ini_section(text, "db").get("db-version", "").strip('"')
    current = _ini_section(text, "backup:current")
    if not major or not current:
        raise PhysicalError(f"{info_path} lists no backups")
    sets = current.items()
    if before is not None:
        # pgBackRest restores from the newest set that stopped before the
        # target; report that one, and refuse when there is none.
        sets = [kv for kv in sets if json.loads(kv[1]).get("backup-timestamp-stop", 0) <= before.timestamp()]
        if not sets:
            raise TargetBeforeBackup(f"no backup in stanza {stanza!r} finished before {before.isoformat()}")
    label, raw = max(sets, key=lambda kv: json.loads(kv[1]).get("backup-timestamp-stop", 0))
    meta = json.loads(raw)
    return {"stanza": stanza, "major": major, "label": label,
            "failed": bool(meta.get("backup-error")),
            "finished": dt.datetime.fromtimestamp(meta["backup-timestamp-stop"], dt.timezone.utc)}


def walg_backup(repo: pathlib.Path, name: str | None, before=None) -> dict:
    """{major, label, finished} for the named (or newest) base backup, from
    its stop sentinel."""
    sentinels = list((repo / "basebackups_005").glob("*_backup_stop_sentinel.json"))
    if not sentinels:
        raise PhysicalError(f"{repo} has no basebackups_005/*_backup_stop_sentinel.json")
    found = []
    for path in sentinels:
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        found.append((path.name[: -len("_backup_stop_sentinel.json")], meta))
    if name and name != "LATEST":
        found = [f for f in found if f[0] == name]
        if not found:
            raise PhysicalError(f"no base backup named {name!r} in {repo}")
    if before is not None:
        found = [f for f in found if _finish(f[1]) <= before]
        if not found:
            raise TargetBeforeBackup(f"no base backup in {repo} finished before {before.isoformat()}")
    label, meta = max(found, key=lambda f: _finish(f[1]))
    version = int(meta["PgVersion"])
    major = str(version // 10000) if version >= 100000 else f"{version // 10000}.{version // 100 % 100}"
    return {"major": major, "label": label, "failed": False, "finished": _finish(meta)}


def _finish(meta: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(meta["FinishTime"].replace("Z", "+00:00"))


# -- the container ---------------------------------------------------------

def tool_image(tool: str, base: str) -> str:
    """A postgres image with the backup tool in it, built once and reused."""
    tag = f"firedrill-{tool}:{base.replace('/', '_').replace(':', '-')}"
    have = docker._run(["docker", "image", "inspect", tag], timeout=60)
    if have.returncode == 0:
        return tag
    if tool == "pgbackrest":
        # The official images carry the PGDG apt repository, which ships
        # pgBackRest built for exactly this distribution.
        dockerfile = (f"FROM {base}\nRUN apt-get update && apt-get install -y "
                      "--no-install-recommends pgbackrest && rm -rf /var/lib/apt/lists/*\n")
    else:
        dockerfile = (f"FROM {base}\nADD --checksum=sha256:{WALG_SHA256} {WALG_URL} /usr/local/bin/wal-g\n"
                      "RUN chmod 755 /usr/local/bin/wal-g\n")
    try:
        built = subprocess.run(["docker", "build", "-q", "-t", tag, "-"], input=dockerfile,
                               capture_output=True, text=True, timeout=900, check=False)
    except subprocess.TimeoutExpired:
        raise docker.TargetError(f"building {tag} timed out") from None
    if built.returncode != 0:
        raise docker.TargetError(f"could not build {tag}: {(built.stderr or '').strip()[-500:]}")
    return tag


_PGBACKREST_SCRIPT = """
set -e
mkdir -p "$PGDATA" /tmp/pgbr/lock /tmp/pgbr/log
chown -R postgres:postgres "$PGDATA" /tmp/pgbr
chmod 700 "$PGDATA"
export PGBACKREST_STANZA={stanza} PGBACKREST_PG1_PATH="$PGDATA"
export PGBACKREST_LOCK_PATH=/tmp/pgbr/lock PGBACKREST_LOG_PATH=/tmp/pgbr/log
{repo_env}
gosu postgres pgbackrest restore --log-level-console=warn {options}
exec docker-entrypoint.sh postgres -c archive_mode=off
"""

_WALG_SCRIPT = """
set -e
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
{repo_env}
gosu postgres wal-g backup-fetch "$PGDATA" {backup}
gosu postgres touch "$PGDATA/recovery.signal"
cat >> "$PGDATA/postgresql.auto.conf" <<'FIREDRILL'
restore_command = 'wal-g wal-fetch %f %p'
{target}
FIREDRILL
exec docker-entrypoint.sh postgres -c archive_mode=off
"""


class PhysicalContainer(docker.Container):
    def __init__(self, major: str, image: str, script: str, repo: pathlib.Path | None, **kw):
        super().__init__(major, **kw)
        self.image = image
        self.script = script
        self.repo = pathlib.Path(repo).resolve() if repo else None

    def _run_argv(self) -> list[str]:
        args = ["docker", "run", "-d", "--name", self.name, "--label", "firedrill=1",
                "-e", "POSTGRES_PASSWORD"]
        for name in sorted(os.environ):
            if name.startswith(_PASS_THROUGH):
                args += ["-e", name]   # by name: the value never enters argv
        if self.repo is not None:
            args += ["-v", f"{self.repo}:{REPO_MOUNT}:ro"]
        return args + ["--entrypoint", "bash", self.image, "-c", self.script]

    def start(self) -> None:
        # The base class hands docker a minimal environment; the pass-through
        # variables have to be in it for `-e NAME` to carry them.
        extra = {k: v for k, v in os.environ.items() if k.startswith(_PASS_THROUGH)}
        env = {"PATH": docker._path(), "POSTGRES_PASSWORD": self.password,
               "HOME": docker._home(), **extra}
        result = docker._run(self._run_argv(), env=env)
        if result.returncode != 0:
            raise docker.TargetError(f"could not start {self.image}: {(result.stderr or '').strip()}")
        self.started = True


def script_for(tool: str, *, repo: bool, stanza: str | None, backup: str | None,
               target: str | None) -> str:
    for label, value in (("stanza", stanza), ("backup", backup)):
        if value is not None and not _NAME.match(value):
            raise PhysicalError(f"{label} {value!r} is not a plain name")
    if target is not None:
        # Interpolated into a shell script and the server's config, so it is
        # held to the one shape it can have -- here, not only at the caller.
        from .pitr import InvalidTarget, check_target
        try:
            target = check_target(target)
        except InvalidTarget as exc:
            raise PhysicalError(str(exc)) from None
    if tool == "pgbackrest":
        options = []
        if backup:
            options.append(f"--set={backup}")
        if target:
            options += ["--type=time", f"--target='{target}'", "--target-action=promote"]
        return _PGBACKREST_SCRIPT.format(
            stanza=stanza, options=" ".join(options),
            repo_env=f"export PGBACKREST_REPO1_PATH={REPO_MOUNT}" if repo else "")
    lines = ""
    if target:
        lines = f"recovery_target_time = '{target}'\nrecovery_target_action = 'promote'"
    return _WALG_SCRIPT.format(
        backup=backup or "LATEST", target=lines,
        repo_env=f"export WALG_FILE_PREFIX={REPO_MOUNT}" if repo else "")


def describe(tool: str, repo: pathlib.Path | None, stanza: str | None,
             backup: str | None, major: str | None, target: str | None = None) -> dict:
    """What is about to be restored. A local repository says for itself; a
    remote one needs --postgres, since firedrill will not guess a major."""
    if repo is not None:
        if not repo.is_dir():
            raise PhysicalError(f"{repo} is not a directory")
        before = parse_target(target) if target else None
        meta = (pgbackrest_backup(repo, stanza, before) if tool == "pgbackrest"
                else walg_backup(repo, backup, before))
        if major and major != meta["major"]:
            meta["pinned_from"] = meta["major"]
            meta["major"] = major
        return meta
    if not major:
        raise PhysicalError("a remote repository cannot be read from here; pass --postgres MAJOR")
    if tool == "pgbackrest" and not stanza:
        raise PhysicalError("a remote pgBackRest repository needs --stanza")
    return {"stanza": stanza, "major": major, "label": backup or "latest",
            "failed": False, "finished": None}


def databases(container) -> list[str]:
    listed = container.sql("select datname from pg_database where not datistemplate order by 1")
    names = [n for n in (listed.stdout or "").split() if n]
    return [n for n in names if n != "postgres"] or ["postgres"]


def user_tables(container, database: str) -> int | None:
    counted = container.sql("select count(*) from pg_tables where schemaname not in "
                            "('pg_catalog', 'information_schema')", database=database)
    try:
        return int(counted.stdout.strip())
    except (ValueError, AttributeError):
        return None


def tool_error(logs: str) -> str:
    """The backup tool's own reason, which is what anyone reads first:
    pgBackRest prints `ERROR: [nnn]: ...`, WAL-G `ERROR: ...`."""
    for line in reversed(logs.splitlines()):
        if "ERROR:" in line and "LOG:" not in line:
            return line.split("ERROR:", 1)[1].strip()[:300]
    return "the server exited before accepting connections"


def _span(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds / 60:.0f}m" if seconds >= 60 else f"{seconds:.0f}s"
    return f"{seconds / 3600:.1f}h" if seconds < 172800 else f"{seconds / 86400:.1f}d"


def age_finding(finished, max_age: float | None, now=None) -> list[Finding]:
    if finished is None or max_age is None:
        return []
    now = now or dt.datetime.now(dt.timezone.utc)
    age = (now - finished).total_seconds()
    if age <= max_age:
        return []
    return [Finding(
        stage="recover", rule="BACKUP_STALE", severity="high",
        message=f"the newest backup finished {_span(age)} ago, past the "
                f"{_span(max_age)} allowed",
        fix="The backup job has stopped, or is failing before it finishes. A "
            "restore of an old backup can still pass; this is the part that is broken.",
        evidence=finished.isoformat(),
    )]


