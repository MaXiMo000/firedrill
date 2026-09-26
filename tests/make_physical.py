"""Real pgBackRest and WAL-G repositories, made by the tools themselves.

Each: a PostgreSQL 16 server archiving WAL, a table `orders`, a full base
backup, then `before_target` created, a timestamp taken, and `after_target`
created -- so a restore to that timestamp has exactly one right answer.

Returns {"pgbackrest": (repo, target), "walg": (repo, target)}. Needs Docker
and the network (apt for pgBackRest, the WAL-G release binary).
"""
from __future__ import annotations

import pathlib
import subprocess
import time
import uuid

from firedrill import physical

_SETUP = {
    "pgbackrest": (
        "apt-get update -qq && apt-get install -y -qq pgbackrest >/dev/null && "
        "mkdir -p /etc/pgbackrest && printf '[global]\\nrepo1-path=/repo\\nstart-fast=y\\n"
        "log-level-console=warn\\n[demo]\\npg1-path=/var/lib/postgresql/data\\n' "
        "> /etc/pgbackrest/pgbackrest.conf && chown -R postgres /repo",
        "pgbackrest --stanza=demo archive-push %p",
        "pgbackrest --stanza=demo stanza-create && pgbackrest --stanza=demo --type=full backup",
    ),
    "walg": (
        "apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null && "
        f"curl -sfL -o /usr/local/bin/wal-g {physical.WALG_URL} && "
        f"echo '{physical.WALG_SHA256}  /usr/local/bin/wal-g' | sha256sum -c - && "
        "chmod 755 /usr/local/bin/wal-g && chown postgres /repo",
        "/usr/local/bin/wal-g wal-push %p",
        "wal-g backup-push \"$PGDATA\"",
    ),
}

_WORKLOAD = """
set -e
export WALG_FILE_PREFIX=/repo PGHOST=/var/run/postgresql
psql -q -c "create database shop"
psql -q -d shop -c "create table orders(id serial primary key, amount int); insert into orders(amount) select g from generate_series(1,5000) g;"
{backup}
psql -q -d shop -c "insert into orders(amount) select g from generate_series(1,1000) g; create table before_target(x int);"
sleep 2; date -u +"%Y-%m-%d %H:%M:%S+00"; sleep 2
psql -q -d shop -c "create table after_target(x int);"
psql -q -c "select pg_switch_wal()" >/dev/null
sleep 12
"""


def _sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, check=True, timeout=900, **kw)


def build(root: pathlib.Path) -> dict:
    out = {}
    for tool, (install, archive_command, backup) in _SETUP.items():
        repo = root / f"{tool}-repo"
        target_file = root / f"{tool}-target"
        if target_file.exists():
            out[tool] = (repo, target_file.read_text().strip())
            continue
        repo.mkdir(parents=True, exist_ok=True)
        repo.chmod(0o777)  # the container's postgres uid writes here
        name = f"firedrill-src-{uuid.uuid4().hex[:8]}"
        # The server's archive_command reads its storage from the environment.
        _sh("docker", "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=x",
            "-e", "WALG_FILE_PREFIX=/repo",
            "-v", f"{repo.resolve()}:/repo", "postgres:16",
            "-c", "wal_level=replica", "-c", "archive_mode=on",
            "-c", f"archive_command={archive_command}", "-c", "archive_timeout=10")
        try:
            for _ in range(60):
                if subprocess.run(["docker", "exec", name, "pg_isready", "-q", "-h", "127.0.0.1"],
                                  capture_output=True).returncode == 0:
                    break
                time.sleep(1)
            _sh("docker", "exec", name, "bash", "-c", install)
            ran = _sh("docker", "exec", "-u", "postgres", name, "bash", "-c",
                      _WORKLOAD.format(backup=backup))
            target = ran.stdout.strip().splitlines()[-1]
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        target_file.write_text(target)
        out[tool] = (repo, target)
    return out
