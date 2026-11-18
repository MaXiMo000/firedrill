"""SQLite: a database file is its own backup, so "restoring" one is copying
it into place and opening it. No container is involved.

The header says how many pages the file should hold, so a copy cut off
part-way -- `cp` of a live file interrupted, an upload that stopped -- is
caught exactly rather than inferred. SQLite's own `integrity_check` and
`foreign_key_check` are the integrity rung, and the user's semantics checks
run unchanged through the same `.sql()` interface the containers offer.
"""
from __future__ import annotations

import dataclasses
import pathlib
import shutil
import sqlite3
import struct

from .finding import Finding

MAGIC = b"SQLite format 3\x00"
SEP = "|"  # what ladder._rows splits on


def detect(path) -> dict | None:
    """{writer_version, page_size, pages, expected_bytes, actual_bytes} for a
    SQLite database file, or None when it is not one."""
    path = pathlib.Path(path)
    try:
        with open(path, "rb") as handle:
            header = handle.read(100)
    except OSError:
        return None
    if len(header) < 100 or not header.startswith(MAGIC):
        return None
    page_size = struct.unpack(">H", header[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    change_counter, pages = struct.unpack(">II", header[24:32])
    valid_for, writer = struct.unpack(">II", header[92:100])
    # The in-header page count is only trustworthy when written by a version
    # that maintains it (3.7.0+), which `version-valid-for` matching proves.
    counted = pages if pages and valid_for == change_counter else None
    return {
        "writer_version": f"{writer // 1000000}.{writer // 1000 % 1000}.{writer % 1000}" if writer else None,
        "page_size": page_size,
        "pages": counted,
        "expected_bytes": counted * page_size if counted else None,
        "actual_bytes": path.stat().st_size,
    }


@dataclasses.dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


class SQLiteTarget:
    """A restored copy, answering `.sql()` the way the containers do."""

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self.conn = sqlite3.connect(self.path)
        # Opening is lazy; reading the schema is what proves the file is a database.
        self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()

    def sql(self, statement: str, database: str = "main", timeout: int = 300) -> Result:
        try:
            rows = self.conn.execute(statement).fetchall()
        except sqlite3.Error as exc:
            return Result(1, "", str(exc))
        return Result(0, "\n".join(SEP.join("" if v is None else str(v) for v in row) for row in rows), "")

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()


def restore(dump_path, workdir: pathlib.Path) -> tuple[SQLiteTarget, list[Finding]]:
    """Copy the database into the scratch directory and open it there: the
    backup itself is never opened, so nothing can write to it."""
    copy = workdir / "restored.sqlite"
    shutil.copyfile(dump_path, copy)
    target = SQLiteTarget(copy)
    try:
        target.open()
    except sqlite3.Error as exc:
        return target, [Finding(
            stage="restore", rule="RESTORE_FAILED", severity="critical",
            message=f"SQLite could not open the backup as a database: {exc}",
            fix="The file has a SQLite header but its contents are not readable. "
                "It is not a usable backup.",
            evidence=str(exc))]
    return target, []


def user_tables(target: SQLiteTarget) -> list[str]:
    result = target.sql("SELECT name FROM sqlite_master WHERE type = 'table' "
                        "AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return result.stdout.splitlines() if result.returncode == 0 else []


def integrity(target: SQLiteTarget) -> list[Finding]:
    findings = []
    check = target.sql("PRAGMA integrity_check")
    problems = [line for line in check.stdout.splitlines() if line != "ok"]
    if check.returncode != 0 or problems:
        message = (f"SQLite's integrity_check stopped on damage: {check.stderr}" if check.returncode
                   else f"SQLite's integrity_check found {len(problems)} problem(s)")
        findings.append(Finding(
            stage="integrity", rule="INTEGRITY_FAILED", severity="critical",
            message=message,
            fix="The database restored but is damaged: pages, indexes or records "
                "do not agree. Restore an earlier backup and find what wrote this one.",
            evidence="\n".join(problems[:20]) or check.stderr))
    keys = target.sql("PRAGMA foreign_key_check")
    violations = keys.stdout.splitlines() if keys.returncode == 0 else []
    if violations:
        tables = sorted({line.split(SEP)[0] for line in violations})
        findings.append(Finding(
            stage="integrity", rule="FOREIGN_KEY_VIOLATION", severity="high",
            message=f"{len(violations)} row(s) in {', '.join(tables)} point at parent rows that do not exist",
            fix="SQLite does not enforce foreign keys unless the application turns "
                "them on, so this can be old. Either way, these rows reference nothing.",
            evidence="\n".join(violations[:20])))
    return findings
