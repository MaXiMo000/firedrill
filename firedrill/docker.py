"""The ephemeral restore target.

Safety notes, because this is the module that could hurt someone (PLAN.md §7):

* firedrill only ever talks to a container it created itself. There is no
  code path here that connects to a DSN, so there is no code path that can be
  pointed at production by accident. The user-supplied-DSN target and its four
  interlocks arrive with a later phase; until then the safest implementation
  of "refuses any target it did not create" is to have no other target.
* No port is published. Everything goes through `docker exec`, so the instance
  is not reachable from the host at all and there is no listening surface to
  bind a password to.
* The generated password is passed by *name* (`-e POSTGRES_PASSWORD`), letting
  Docker inherit the value from our environment. Passing `-e VAR=value` would
  put it in argv, and /proc/*/cmdline is world-readable. It is never written
  to disk and it is registered with finding.redact() so it cannot reach a
  report even by accident.
* The dump is bind-mounted read-only. "Never writes to the source" is then a
  property of the mount rather than a promise about our own code.
"""

from __future__ import annotations

import pathlib
import secrets
import shutil
import subprocess
import time
import uuid

from . import finding

LABEL = "firedrill"
CONTAINER_PREFIX = "firedrill-"

# Where the archive appears inside the container. Fixed, so nothing has to
# interpolate a host path into a command.
DUMP_PATH = "/firedrill/dump"

DEFAULT_READY_TIMEOUT = 120


class DockerUnavailable(Exception):
    """Docker cannot be used. This is reported, never silently skipped."""


class TargetError(Exception):
    """The container could not be brought up or used."""


def _run(args: list[str], env: dict | None = None, timeout: int = 300):
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env, check=False
    )


def docker_available() -> tuple[bool, str]:
    """(usable, why-not). The 'why-not' is the whole point of this function.

    A missing daemon must produce a stated reason in the report. 'Could not be
    verified' is a legitimate outcome; a green tick because the restore never
    ran is not.
    """
    if shutil.which("docker") is None:
        return False, "the `docker` command is not on PATH"
    try:
        result = _run(["docker", "info", "--format", "{{.ServerVersion}}|{{.OSType}}"],
                      timeout=30)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"`docker info` did not complete: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        return False, detail[-1] if detail else "`docker info` failed"

    server_version, _, os_type = result.stdout.strip().partition("|")

    # Measured on the ubuntu-24.04 runner: with an unreachable daemon,
    # `docker info --format ...` exits 0 and prints an empty server version.
    # Trusting the exit code therefore reported a dead daemon as usable, and
    # the drill fell through to the container-start path instead of saying it
    # could not verify anything. This tool exists to distrust exactly that kind
    # of exit code, so the probe checks the capability, not the status.
    if not server_version:
        return False, ("`docker info` returned no server version, so the daemon "
                       "is not reachable")

    # A Windows daemon in Windows-container mode answers `docker info` happily
    # and then cannot pull a linux-only postgres image. Unusable is the honest
    # answer, and it makes the container tests skip by name rather than die
    # halfway through with a pull error.
    if os_type and os_type != "linux":
        return False, (f"the docker daemon is in {os_type}-container mode; the "
                       "postgres images firedrill restores into are linux-only")

    return True, server_version


def image_for(major: str, flavour: str = "") -> str:
    """postgres:16 -- Debian, deliberately.

    The alpine variants are musl libc. Restoring a glibc-built production dump
    into musl guarantees a collation-environment mismatch, which is precisely
    the silent corruption PLAN.md §3.4 exists to detect. Defaulting to alpine
    would mean the default target poisons the tool's own flagship check.
    """
    return f"postgres:{major}{flavour}"


class Container:
    """A disposable, version-matched Postgres. Use as a context manager."""

    def __init__(self, major: str, dump: pathlib.Path | None = None,
                 flavour: str = "", ready_timeout: int = DEFAULT_READY_TIMEOUT):
        self.major = major
        self.image = image_for(major, flavour)
        self.dump = pathlib.Path(dump).resolve() if dump else None
        self.ready_timeout = ready_timeout
        self.name = CONTAINER_PREFIX + uuid.uuid4().hex[:12]
        self.password = secrets.token_urlsafe(24)
        finding.register_secret(self.password)
        self.started = False

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "Container":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()

    def _run_argv(self) -> list[str]:
        """The `docker run` command. A seam, so a subclass can start the same
        image a different way -- pitr.RecoveryContainer seeds PGDATA from a base
        backup instead of letting the entrypoint run initdb."""
        args = [
            "docker", "run", "-d",
            "--name", self.name,
            "--label", f"{LABEL}=1",
            # Value omitted on purpose: docker reads it from our environment
            # instead of taking it through argv. See the module docstring.
            "-e", "POSTGRES_PASSWORD",
            "-e", "POSTGRES_INITDB_ARGS=--data-checksums",
        ]
        if self.dump is not None:
            args += ["-v", f"{self.dump}:{DUMP_PATH}:ro"]
        args.append(self.image)
        return args

    def start(self) -> None:
        args = self._run_argv()
        env = {"PATH": _path(), "POSTGRES_PASSWORD": self.password, "HOME": _home()}
        result = _run(args, env=env)
        if result.returncode != 0:
            raise TargetError(
                f"could not start {self.image}: {(result.stderr or '').strip()}"
            )
        self.started = True

    def wait_ready(self) -> None:
        """Block until Postgres answers, or say why it never did."""
        deadline = time.monotonic() + self.ready_timeout
        last = ""
        while time.monotonic() < deadline:
            # Over TCP, deliberately. During initdb the official entrypoint runs a
            # temporary server with `listen_addresses=''` (docker-entrypoint.sh,
            # docker_temp_server_start) to execute init scripts, then stops it and
            # starts the real one. A unix-socket probe answers "ready" during that
            # window, so a restore could begin against a server that is about to be
            # shut down -- an intermittent failure that would look like a corrupt
            # dump. TCP cannot reach the temp server, so it only says yes once.
            probe = self.exec(
                ["pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-q"], timeout=30
            )
            if probe.returncode == 0:
                return
            last = (probe.stderr or probe.stdout or "").strip()
            # A container that died will never become ready; fail now rather
            # than spending the full timeout on a corpse.
            if not self.running():
                raise TargetError(
                    f"{self.image} exited before accepting connections.\n{self.logs()}"
                )
            time.sleep(0.5)
        raise TargetError(
            f"{self.image} did not accept connections within {self.ready_timeout}s. "
            f"Last probe: {last}\n{self.logs()}"
        )

    def running(self) -> bool:
        result = _run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.name], timeout=30
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    def logs(self, tail: int = 20) -> str:
        result = _run(["docker", "logs", "--tail", str(tail), self.name], timeout=30)
        return finding.redact((result.stdout or "") + (result.stderr or ""))

    def teardown(self) -> None:
        if not self.started:
            return
        _run(["docker", "rm", "-f", "-v", self.name], timeout=120)
        self.started = False

    # -- use ---------------------------------------------------------------

    def exec(self, argv: list[str], timeout: int = 3600, user: str = "postgres"):
        """Run a command inside the container, as postgres unless told otherwise.

        `user="root"` exists for one reason: reading the mounted dump. pg_dump
        writes a -Fd directory with mode 700, and a -Fc file is often 600, both
        owned by whoever ran it. The postgres user inside this container is a
        different uid, so on Linux it frequently cannot read the backup at all
        -- measured: a directory dump restored ZERO tables on a CI runner while
        working on macOS, where Docker Desktop's file sharing hides the
        mismatch.

        Only the client that reads the mount runs as root. It is a client, not
        the server; the container is disposable, has no published port, and the
        mount is read-only.
        """
        return _run(["docker", "exec", "-u", user, self.name, *argv],
                    timeout=timeout)

    def sql(self, statement: str, database: str = "postgres", timeout: int = 300):
        return self.exec(
            ["psql", "-U", "postgres", "-d", database, "-tAc", statement],
            timeout=timeout,
        )


def _path() -> str:
    import os
    return os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")


def _home() -> str:
    import os
    return os.environ.get("HOME", "/tmp")


def orphans() -> list[str]:
    """Containers this tool left behind, findable by label."""
    result = _run(
        ["docker", "ps", "-aq", "--filter", f"label={LABEL}=1", "--format", "{{.Names}}"],
        timeout=60,
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.split() if line]


def clean() -> list[str]:
    removed = []
    for name in orphans():
        if _run(["docker", "rm", "-f", "-v", name], timeout=120).returncode == 0:
            removed.append(name)
    return removed
