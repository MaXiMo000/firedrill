"""MySQL and MariaDB dumps: the same promise, a second engine.

`mysqldump` output has the two properties firedrill's plain-SQL Postgres
support rests on: a header naming the server version, and a trailer
(`-- Dump completed on ...`) written only when the dump finished. So the
version is read from the file, the restore runs in a container of that
same version, and a dump without its trailer is truncated before anything
is restored.

MariaDB's `mariadb-dump` writes the same shape and says so in its header;
its 11.x images ship `mariadb*` clients only, so the client name follows the
engine.
"""
from __future__ import annotations

import gzip
import pathlib
import re

from . import docker
from .finding import Finding

_HEAD = re.compile(r"^-- (MySQL|MariaDB) dump ")
_SERVER = re.compile(r"^-- Server version\s+(\d+)\.(\d+)\.\d+(-MariaDB)?", re.M)
_TRAILER = "-- Dump completed"
# ERROR 1064 (42000) at line 12: You have an error in your SQL syntax ...
_CLIENT_ERROR = re.compile(r"^ERROR (\d+) \(([0-9A-Z]{5})\)(?: at line (\d+))?: (.*)$", re.M)
_SYSTEM_SCHEMAS = ("mysql", "sys", "information_schema", "performance_schema")


def _open(path: pathlib.Path):
    with open(path, "rb") as handle:
        magic = handle.read(2)
    return gzip.open(path, "rb") if magic == b"\x1f\x8b" else open(path, "rb")


def detect(path) -> dict | None:
    """{engine, version, gzipped, complete} for a mysqldump/mariadb-dump
    file, or None when it is not one."""
    path = pathlib.Path(path)
    if not path.is_file():
        return None
    try:
        with _open(path) as handle:
            head = handle.read(4096).decode("utf-8", errors="replace")
    except (OSError, EOFError):
        return None
    # MariaDB 10.5.25+/11.x dumps open with `/*M!999999\- enable the sandbox
    # mode */` before the header -- the line that makes them unloadable into
    # MySQL. Skipped here, so every modern MariaDB dump is still recognised.
    lines = head.splitlines()
    if lines and lines[0].startswith("/*M!999999"):
        head = "\n".join(lines[1:])
    if not _HEAD.match(head):
        return None
    server = _SERVER.search(head)
    engine = "mariadb" if (server and server.group(3)) or head.startswith("-- MariaDB") else "mysql"
    version = f"{server.group(1)}.{server.group(2)}" if server else None
    gzipped = _is_gz(path)
    return {"engine": engine, "version": version, "gzipped": gzipped,
            "complete": _TRAILER in _tail(path, gzipped)}


def _is_gz(path) -> bool:
    with open(path, "rb") as handle:
        return handle.read(2) == b"\x1f\x8b"


def _tail(path: pathlib.Path, gzipped: bool, size: int = 512) -> str:
    """The last bytes of the (decompressed) dump. A .gz is streamed through,
    and a .gz that is itself cut short reads as incomplete."""
    if not gzipped:
        with open(path, "rb") as handle:
            handle.seek(max(0, path.stat().st_size - size))
            return handle.read().decode("utf-8", errors="replace")
    last = b""
    try:
        with gzip.open(path, "rb") as handle:
            while chunk := handle.read(1 << 20):
                last = (last + chunk)[-size:]
    except (OSError, EOFError):
        return ""
    return last.decode("utf-8", errors="replace")


def image_for(engine: str, version: str, flavour: str = "") -> str:
    if "{major}" in flavour:
        return flavour.format(major=version)
    return f"{engine}:{version}{flavour}"


def _client(engine: str, version: str, tool: str) -> str:
    """mysql, mysqladmin, mysqlcheck -- or mariadb, mariadb-admin, mariadb-check,
    which is all MariaDB 11 images still ship."""
    if engine == "mariadb":
        return {"mysql": "mariadb", "mysqladmin": "mariadb-admin", "mysqlcheck": "mariadb-check"}[tool]
    return tool


class MySQLContainer(docker.Container):
    """A disposable MySQL/MariaDB of the dump's own version."""

    def __init__(self, engine: str, version: str, dump, flavour: str = "",
                 ready_timeout: int = docker.DEFAULT_READY_TIMEOUT):
        super().__init__(version, dump=dump, ready_timeout=ready_timeout)
        self.engine = engine
        self.image = image_for(engine, version, flavour)

    def _cmd(self, tool: str) -> str:
        return _client(self.engine, self.major, tool)

    def _run_argv(self) -> list[str]:
        # By name, never value -- same rule as the Postgres target.
        return ["docker", "run", "-d", "--name", self.name, "--label", f"{docker.LABEL}=1",
                "-e", "MYSQL_ROOT_PASSWORD", "-e", "MARIADB_ROOT_PASSWORD",
                "-v", f"{self.dump}:{docker.DUMP_PATH}:ro", self.image]

    def start(self) -> None:
        env = {"PATH": docker._path(), "HOME": docker._home(),
               "MYSQL_ROOT_PASSWORD": self.password, "MARIADB_ROOT_PASSWORD": self.password}
        result = docker._run(self._run_argv(), env=env)
        if result.returncode != 0:
            raise docker.TargetError(f"could not start {self.image}: {(result.stderr or '').strip()}")
        self.started = True

    def shell(self, script: str, timeout: int = 3600):
        """A command with the client's password in MYSQL_PWD, read inside the
        container from its own environment -- never through argv."""
        # Exported, not prefixed: a prefix applies only to the first command
        # of a pipeline, so `cat dump | mysql` logged in with no password.
        return self.exec(["sh", "-c", f'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; {script}'],
                         timeout=timeout, user="root")

    def wait_ready(self) -> None:
        # Over TCP: like the Postgres image, the entrypoint runs a temporary
        # server with networking off while it initialises.
        import time
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            probe = self.shell(f"{self._cmd('mysqladmin')} -h127.0.0.1 -uroot ping", timeout=30)
            if probe.returncode == 0:
                return
            if not self.running():
                raise docker.TargetError(f"{self.image} exited before accepting connections.\n{self.logs()}")
            time.sleep(1)
        raise docker.TargetError(f"{self.image} did not accept connections within "
                                 f"{self.ready_timeout}s\n{self.logs()}")

    def sql(self, statement: str, database: str = "mysql", timeout: int = 300):
        quoted = statement.replace("'", "'\"'\"'")
        return self.shell(f"{self._cmd('mysql')} -h127.0.0.1 -uroot -N -B -D {database} -e '{quoted}'",
                          timeout=timeout)


def restore(container: MySQLContainer, gzipped: bool) -> tuple[int, list[Finding], str]:
    reader = "gunzip -c" if gzipped else "cat"
    result = container.shell(
        f"{reader} {docker.DUMP_PATH} | {container._cmd('mysql')} -h127.0.0.1 -uroot")
    stderr = "\n".join(l for l in (result.stderr or "").splitlines()
                       if "Using a password on the command line" not in l)
    findings = []
    for code, state, line, message in _CLIENT_ERROR.findall(stderr):
        findings.append(Finding(
            stage="restore", rule="RESTORE_ERROR", severity="high",
            message=f"ERROR {code} ({state}){f' at line {line}' if line else ''}: {message.strip()}",
            fix="The mysql client stops at the first failing statement, so "
                "everything after this line of the dump was never restored.",
            evidence=""))
    if result.returncode != 0 and not findings:
        findings.append(Finding(
            stage="restore", rule="RESTORE_FAILED", severity="critical",
            message=f"the restore exited {result.returncode}",
            fix="An unexplained non-zero exit is not evidence of success.",
            evidence=stderr.strip()[-500:] or "(no stderr)"))
    return result.returncode, findings, stderr


def schemas(container: MySQLContainer) -> dict[str, int]:
    listed = container.sql(
        "select table_schema, count(*) from information_schema.tables where table_schema "
        f"not in {tuple(_SYSTEM_SCHEMAS)} group by table_schema order by 1")
    out = {}
    for line in (listed.stdout or "").splitlines():
        name, _, count = line.partition("\t")
        if count.strip().isdigit():
            out[name] = int(count)
    return out


def check_tables(container: MySQLContainer, databases: list[str]) -> list[Finding]:
    """CHECK TABLE on every restored table: the engine's own verdict on each.
    Plain SQL rather than mysqlcheck, which the mysql:8.4 image doesn't ship."""
    if not databases:
        return []
    listed = container.sql(
        "select concat('`', table_schema, '`.`', table_name, '`') from information_schema.tables "
        f"where table_type = 'BASE TABLE' and table_schema in {tuple(databases) + ('',)}")
    tables = [t for t in (listed.stdout or "").split() if t]
    if listed.returncode != 0:
        return [Finding(stage="integrity", rule="TABLE_CHECK_UNRUNNABLE", severity="high",
                        message="could not list the restored tables",
                        fix="Nothing about table integrity has been proved.",
                        evidence=(listed.stderr or "").strip()[-300:])]
    findings = []
    for i in range(0, len(tables), 50):
        ran = container.sql("check table " + ", ".join(tables[i:i + 50]))
        if ran.returncode != 0:
            findings.append(Finding(stage="integrity", rule="TABLE_CHECK_UNRUNNABLE", severity="high",
                                    message="CHECK TABLE could not run",
                                    fix="Nothing about table integrity has been proved.",
                                    evidence=(ran.stderr or "").strip()[-300:]))
            continue
        # Table  Op  Msg_type  Msg_text -- anything but "status OK" is the
        # engine saying the table is not sound.
        for row in (ran.stdout or "").splitlines():
            cols = row.split("\t")
            if len(cols) == 4 and not (cols[2] == "status" and cols[3] == "OK") and cols[2] != "note":
                findings.append(Finding(stage="integrity", rule="TABLE_CHECK_FAILED", severity="high",
                                        message=f"CHECK TABLE {cols[0]}: {cols[2]} {cols[3]}",
                                        fix="The engine itself reports this table as damaged.",
                                        evidence=""))
    return findings
