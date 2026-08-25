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
        raise SourceError(f"{path} is a directory; firedrill reads a single archive")
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


_FETCHERS = {"local": _fetch_local, "https": _fetch_https, "s3": _fetch_s3}


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
