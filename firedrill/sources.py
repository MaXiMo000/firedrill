"""Where backups actually live: a local path, a presigned URL, or S3.

Every source here is **read-only by construction**. There is no code path in
this module that writes, deletes, copies or tags anything at the origin --
not because we promise not to, but because the verbs are absent. PLAN.md §7's
"never writes to the source" is then a property of the file rather than a
claim in a README.

Credentials come from the environment only. There is no --access-key and no
way to put one in firedrill.yml, because `/proc/*/cmdline` is world-readable
and CI logs echo command lines. boto3's default chain (env, profile, IMDS,
SSO) already does exactly the right thing, which is most of the argument for
depending on it rather than signing requests here.

The fetched artefact is verified against what the backup job claimed before
anything tries to restore it. A dump that arrives truncated but plausible is
the failure this whole project exists to catch, so it is caught at the door.
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import shutil
import urllib.error
import urllib.parse
import urllib.request
from subprocess import PIPE as subprocess_PIPE

from . import finding

# Big enough that hashing is not the bottleneck, small enough that a 2 TB
# artefact does not arrive in memory.
CHUNK = 1024 * 1024

# http:// is permitted only for these, so a typo'd scheme cannot send a
# presigned URL -- which carries its own credentials in the query string --
# over the network in clear text. Local test servers still work.
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "minio")


class SourceError(Exception):
    """The artefact could not be obtained, or is not what was promised."""


@dataclasses.dataclass
class Artifact:
    path: pathlib.Path
    size: int
    sha256: str
    origin: str            # safe to print: never carries a query string
    fetch_seconds: float = 0.0


def _digest(path: pathlib.Path) -> tuple[int, str]:
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            sha.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest()


def _safe_origin(url: str) -> str:
    """A URL with its query string removed.

    A presigned URL's signature IS a credential. It must never reach a report,
    a log line or a finding, and stripping it here means no caller has to
    remember that.
    """
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


# ------------------------------------------------------------------- local --

def _fetch_local(source, workdir: pathlib.Path) -> Artifact:
    path = pathlib.Path(source.path).expanduser()
    if not path.exists():
        raise SourceError(f"no such file: {path}")

    if path.is_dir():
        # A directory-format dump (`pg_dump -Fd`) is a real archive, and the
        # shape large databases are dumped in because it restores in parallel.
        if not (path / "toc.dat").exists():
            raise SourceError(
                f"{path} is a directory with no toc.dat in it, so it is not a "
                "directory-format dump. Point at the dump directory itself, or "
                "at a single -Fc/-Ft archive."
            )
        if source.sha256:
            # A tree has no single checksum without inventing a canonical form
            # for it. Refused rather than quietly ignored, which would leave the
            # config claiming a verification that never happened.
            raise SourceError(
                "source.sha256 cannot be checked against a directory dump: a "
                "directory has no single digest. Use `size`, or dump to a "
                "single-file format if you want a checksum."
            )
        total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        return Artifact(path=path, size=total, sha256="", origin=str(path))

    # Not copied. Reading it in place cannot modify it, and copying a 2 TB
    # backup to check it is restorable is its own outage.
    return Artifact(path=path, size=path.stat().st_size, sha256="", origin=str(path))


# ------------------------------------------------------------------- https --

def _fetch_https(source, workdir: pathlib.Path) -> Artifact:
    url = source.url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise SourceError(
            f"source.url must be http(s), got {parts.scheme!r}. file:// is "
            "refused here: use `type: local` so that reading a local path is "
            "an explicit choice rather than a URL that happens to resolve."
        )
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS:
        raise SourceError(
            f"refusing plain http to {parts.hostname!r}. A presigned URL "
            "carries its signature in the query string, so http would put a "
            "working credential on the wire in clear text. Use https."
        )

    destination = workdir / "artefact.dump"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=300) as response, \
                destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, CHUNK)
    except urllib.error.HTTPError as exc:
        raise SourceError(
            f"{_safe_origin(url)} returned HTTP {exc.code}. If this is a "
            "presigned URL it may simply have expired."
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourceError(f"could not fetch {_safe_origin(url)}: {exc}") from None

    size, sha = _digest(destination)
    return Artifact(path=destination, size=size, sha256=sha, origin=_safe_origin(url))


# ---------------------------------------------------------------------- s3 --

def _boto3():
    try:
        import boto3  # noqa: F401
    except ModuleNotFoundError:
        raise SourceError(
            "the s3 source needs boto3, which is an optional extra: "
            "`pip install firedrill[s3]`. It is not a base dependency because "
            "most users restore from a local path or a presigned URL, and "
            "boto3 is large."
        ) from None
    return __import__("boto3")


def _fetch_s3(source, workdir: pathlib.Path) -> Artifact:
    boto3 = _boto3()
    client = boto3.client("s3", endpoint_url=source.endpoint_url or None,
                          region_name=source.region or None)

    key = source.key
    if key is None:
        key = _newest_key(client, source)

    destination = workdir / "artefact.dump"
    try:
        client.download_file(source.bucket, key, str(destination))
    except Exception as exc:  # botocore raises a wide family; all mean the same
        raise SourceError(
            f"could not download s3://{source.bucket}/{key}: "
            f"{type(exc).__name__}: {exc}"
        ) from None

    size, sha = _digest(destination)
    return Artifact(path=destination, size=size, sha256=sha,
                    origin=f"s3://{source.bucket}/{key}")


def _newest_key(client, source) -> str:
    """The most recently modified object under a prefix.

    This is what people actually want -- "last night's backup" -- and nobody
    hardcodes a key with a date in it. Needs ListObjects as well as GetObject,
    which is worth saying out loud when the read-only policy is written.
    """
    newest = None
    paginator = client.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=source.bucket, Prefix=source.prefix or ""):
            for item in page.get("Contents", ()):
                if item["Key"].endswith("/"):
                    continue
                if newest is None or item["LastModified"] > newest["LastModified"]:
                    newest = item
    except Exception as exc:
        raise SourceError(
            f"could not list s3://{source.bucket}/{source.prefix or ''}: "
            f"{type(exc).__name__}: {exc}"
        ) from None

    if newest is None:
        raise SourceError(
            f"nothing to restore: s3://{source.bucket}/{source.prefix or ''} is "
            "empty. Reported rather than passed -- a backup that is not there "
            "is the most complete failure there is, and it is silent."
        )
    return newest["Key"]


# -------------------------------------------------------------------- live --

# pg_dump can dump any server at or below its own major, so the probe only
# needs to be recent; the dump itself then runs from the server's own major.
_PROBE_IMAGE = "postgres:17"
_LOOPBACK = ("localhost", "127.0.0.1", "::1")


def _live_dsn(source) -> tuple[str, str]:
    """(dsn as the container sees it, a printable origin with no userinfo)."""
    import os
    dsn = os.environ.get(source.url_env or "")
    if not dsn:
        raise SourceError(
            f"${source.url_env} is not set. The live source reads the database "
            "URL from an environment variable, never from argv or the config, "
            "because both end up in logs."
        )
    parts = urllib.parse.urlsplit(dsn)
    if parts.scheme not in ("postgres", "postgresql"):
        raise SourceError(f"${source.url_env} is not a postgres:// URL")
    if parts.password:
        finding.register_secret(parts.password)
    host = parts.hostname or "localhost"
    netloc = parts.netloc
    if host in _LOOPBACK:
        # Inside the container, localhost is the container. The host is
        # host.docker.internal (mapped with --add-host on Linux).
        userinfo, at, _ = netloc.rpartition("@")
        netloc = f"{userinfo}{at}host.docker.internal" + (f":{parts.port}" if parts.port else "")
    inside = urllib.parse.urlunsplit(parts._replace(netloc=netloc))
    shown = f"postgres://{host}{f':{parts.port}' if parts.port else ''}{parts.path}"
    return inside, shown


def _pg(image: str, script: str, dsn: str, stdout=subprocess_PIPE, timeout=None):
    import os
    import subprocess
    # The DSN goes in by *name*: docker inherits the value from our
    # environment, so the password never appears in any argv.
    argv = ["docker", "run", "--rm", "-i", "-e", "FIREDRILL_DSN",
            "--add-host", "host.docker.internal:host-gateway",
            image, "sh", "-c", script]
    try:
        return subprocess.run(argv, stdout=stdout, stderr=subprocess.PIPE,
                              env={**os.environ, "FIREDRILL_DSN": dsn},
                              timeout=timeout, check=False)
    except FileNotFoundError:
        raise SourceError("the live source runs pg_dump in a container, and "
                          "`docker` is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise SourceError(f"pg_dump did not finish within {timeout}s") from None


def _fetch_live(source, workdir: pathlib.Path) -> Artifact:
    """Take a fresh `pg_dump -Fc` of a running database, then drill that.

    Read-only like every other source: pg_dump opens one repeatable-read
    transaction and issues no writes. It runs from the server's own major
    version, so nothing but Docker has to be installed.
    """
    import datetime
    dsn, shown = _live_dsn(source)
    probe = _pg(_PROBE_IMAGE, 'psql -d "$FIREDRILL_DSN" -XAtc "show server_version_num"',
                dsn, timeout=120)
    if probe.returncode != 0:
        raise SourceError(f"could not connect to {shown}: "
                          f"{finding.redact(probe.stderr.decode(errors='replace')).strip()[-300:]}")
    major = str(int(probe.stdout.decode().strip()) // 10000)

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    database = urllib.parse.urlsplit(dsn).path.strip("/") or "postgres"
    folder = pathlib.Path(source.keep).expanduser() if source.keep else workdir
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / f"{database}-{stamp}.dump"
    with destination.open("wb") as handle:
        dump = _pg(f"postgres:{major}", 'exec pg_dump -Fc --no-password -d "$FIREDRILL_DSN"',
                   dsn, stdout=handle)
    if dump.returncode != 0:
        destination.unlink(missing_ok=True)
        raise SourceError(f"pg_dump of {shown} failed: "
                          f"{finding.redact(dump.stderr.decode(errors='replace')).strip()[-300:]}")

    size, sha = _digest(destination)
    return Artifact(path=destination, size=size, sha256=sha, origin=shown)


def from_argument(arg: str):
    """`s3://bucket/key`, or `s3://bucket/prefix/` for the newest object
    under it. None for anything else, which is then a local path."""
    from .config import Source
    if not arg.startswith("s3://"):
        return None
    bucket, _, rest = arg[len("s3://"):].partition("/")
    if not bucket:
        raise SourceError(f"{arg} names no bucket")
    if not rest or rest.endswith("/"):
        return Source(type="s3", bucket=bucket, prefix=rest)
    return Source(type="s3", bucket=bucket, key=rest)


_FETCHERS = {"local": _fetch_local, "https": _fetch_https, "s3": _fetch_s3,
             "live": _fetch_live}


def fetch(source, workdir: pathlib.Path) -> Artifact:
    """Obtain the artefact and check it is what the backup job claimed."""
    import time
    fetcher = _FETCHERS.get(source.type)
    if fetcher is None:
        raise SourceError(f"unknown source type {source.type!r}")

    started = time.monotonic()
    artifact = fetcher(source, workdir)
    artifact.fetch_seconds = time.monotonic() - started

    verify(source, artifact)
    return artifact


def verify(source, artifact: Artifact) -> None:
    """Size and checksum against what was claimed. Raises, never warns."""
    if source.size is not None and artifact.size != source.size:
        raise SourceError(
            f"{artifact.origin} is {artifact.size} bytes, and the config says "
            f"it should be {source.size}. A short file is what a backup job "
            "that ran out of disk leaves behind, and pg_dump can exit 0 having "
            "written one."
        )

    if source.sha256 is not None:
        actual = artifact.sha256 or _digest(artifact.path)[1]
        if actual.lower() != source.sha256.lower():
            raise SourceError(
                f"{artifact.origin} does not match the sha256 in the config.\n"
                f"  expected {source.sha256.lower()}\n"
                f"  actual   {actual.lower()}\n"
                "The bytes are not the bytes that were backed up. Restoring "
                "them would prove nothing about the backup you meant to test."
            )
