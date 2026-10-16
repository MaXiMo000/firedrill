"""`firedrill demo`: the whole argument in one command, no backup of your own.

Builds a small database in a disposable container, takes a real plain-SQL
pg_dump of it, and makes a second copy cut off part-way through -- what a
backup job killed by a full disk or an OOM leaves behind. It shows that psql
restores the cut copy with exit 0, then drills both copies.

Everything runs in containers firedrill created and removes; nothing is
written outside a temporary directory.
"""
from __future__ import annotations

import pathlib
import subprocess
import tempfile

from . import config, docker, drill, report as reporting

MAJOR = "16"
ROWS = 2000
CUT_AT = 0.6

SCHEMA = f"""
create table customer (
    id serial primary key,
    email text not null unique,
    created_at timestamptz not null default now()
);
insert into customer (email)
    select 'customer' || g || '@example.com' from generate_series(1, {ROWS}) g;
create table orders (
    id serial primary key,
    customer_id int not null references customer(id),
    total_cents int not null
);
insert into orders (customer_id, total_cents)
    select 1 + (g % {ROWS}), 100 + (g * 37) % 9000 from generate_series(1, {ROWS * 2}) g;
"""


def _psql_exit(container: docker.Container, sql: str) -> int:
    """psql's own verdict on a plain dump: create a database, feed it the
    script on stdin, return the exit code a backup script would check."""
    container.sql("create database psql_check")
    result = subprocess.run(
        ["docker", "exec", "-i", "-u", "postgres", container.name,
         "psql", "-q", "-U", "postgres", "-d", "psql_check"],
        input=sql, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600, check=False)
    return result.returncode


def run(out=print) -> int:
    usable, why = docker.docker_available()
    if not usable:
        out(f"docker is not usable: {why}\nRun `firedrill doctor` for details.")
        return 1

    with tempfile.TemporaryDirectory(prefix="firedrill-demo-") as tmp:
        good = pathlib.Path(tmp) / "backup.sql"
        cut = pathlib.Path(tmp) / "backup-cut.sql"

        out(f"building a sample database in postgres:{MAJOR} ...")
        with docker.Container(MAJOR) as source:
            source.wait_ready()
            made = source.exec(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "postgres",
                                "-d", "postgres", "-c", SCHEMA])
            if made.returncode != 0:
                out(f"could not build the sample database: {made.stderr.strip()}")
                return 1
            dumped = source.exec(["pg_dump", "-U", "postgres", "-d", "postgres"])
            if dumped.returncode != 0:
                out(f"pg_dump failed: {dumped.stderr.strip()}")
                return 1
            text = dumped.stdout
            good.write_text(text, encoding="utf-8", newline="\n")
            cut.write_text(text[: int(len(text) * CUT_AT)], encoding="utf-8", newline="\n")
            psql_code = _psql_exit(source, cut.read_text(encoding="utf-8"))

        out(f"  pg_dump      backup.sql      {good.stat().st_size:,} bytes, "
            f"{ROWS:,} customers, {ROWS * 2:,} orders")
        out(f"  cut off      backup-cut.sql  {cut.stat().st_size:,} bytes "
            f"(first {int(CUT_AT * 100)}%, as a killed backup job leaves it)")
        out(f"  psql restores backup-cut.sql: exit {psql_code}"
            + ("  <- what most backup checks look at" if psql_code == 0 else ""))

        results = []
        for label, path in (("1/2  the complete backup", good),
                            ("2/2  the cut-off backup", cut)):
            out(f"\n{label}\n")
            report = drill.run(path, cfg=config.DEFAULT)
            out(reporting.human(report))
            results.append(report)

    complete, broken = results
    rules = sorted({f.rule for f in broken.findings})
    caught = complete.exit_code == 0 and broken.exit_code != 0
    out(f"\ncomplete backup: {'PASS' if complete.exit_code == 0 else 'FAIL'}   "
        f"cut-off backup: {'FAIL' if broken.exit_code else 'PASS'}"
        + (f" ({', '.join(rules)})" if rules else ""))
    if caught and psql_code == 0:
        out("firedrill caught what psql's exit code did not.")
    elif not caught:
        out("unexpected result: the demo did not separate the two backups. "
            "Please report this with the output above.")
    return 0 if caught else 1
