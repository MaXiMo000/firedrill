"""Read a pg_dump custom-format header in pure Python.

Why not shell out to `pg_restore --list`? Because of a bootstrap problem: the
whole point of §3.2 is to start a container matching the dump's server version,
and you cannot ask a version-matched container what version to be. Something
has to read the header before any container exists. Doing it here means the
host needs no Postgres client at all -- which is what lets firedrill run on a
laptop with no Postgres installed, and on a CI runner that cannot run Linux
containers.

The layout below was not taken from documentation. It was decoded byte by byte
from real dumps produced by PostgreSQL 14, 16 and 18 (archive versions 1.14,
1.15 and 1.16) and cross-checked against `pg_restore --list` output for the
same files. tests/test_firedrill.py pins it against committed header bytes.

    offset  bytes  meaning
    0       5      magic "PGDMP"
    5       1      archive version major
    6       1      archive version minor
    7       1      archive version revision
    8       1      sizeof(int) used for Int fields
    9       1      sizeof(off_t)
    10      1      format: 1=custom 3=tar 5=directory
    11      *      compression: one raw byte from archive 1.15 onward,
                   an Int before that (PG 15 and earlier)
    ...     *      7 Ints: sec, min, hour, mday, mon, year, isdst
    ...     *      Str dbname
    ...     *      Str server version    <- the one we came for
    ...     *      Str pg_dump version

Int is a sign byte followed by `intSize` little-endian bytes.
Str is an Int length followed by that many bytes; a negative length is NULL.
"""

from __future__ import annotations

import dataclasses
import gzip
import pathlib
import re
import tarfile
import zlib

MAGIC = b"PGDMP"

FORMAT_PLAIN = 0  # firedrill's own code: plain SQL has no archive header to carry one
FORMAT_CUSTOM = 1
FORMAT_TAR = 3
FORMAT_DIRECTORY = 5

_FORMAT_NAMES = {0: "plain", 1: "custom", 3: "tar", 5: "directory"}

# Everything firedrill can restore: pg_restore reads the three archive
# formats (a directory dump's toc.dat reports format 3, tar, which is why
# both share one code), and psql reads plain SQL.
RESTORABLE_FORMATS = (FORMAT_PLAIN, FORMAT_CUSTOM, FORMAT_TAR, FORMAT_DIRECTORY)

# From this archive version the compression field is a single raw byte rather
# than an Int. Verified: PG 14 -> 1.14 (Int), PG 16 -> 1.15 (byte),
# PG 18 -> 1.16 (byte).
_COMPRESSION_IS_BYTE_FROM = (1, 15)


class ArchiveError(Exception):
    """The archive could not be read. Never a pass -- always a finding."""


@dataclasses.dataclass(frozen=True)
class ArchiveHeader:
    archive_version: tuple[int, int, int]
    int_size: int
    offset_size: int
    format: int
    compression: int
    dbname: str | None
    server_version: str | None
    pgdump_version: str | None
    # Plain SQL only. An archive's completeness shows up as a restore error;
    # a plain dump's doesn't (see read_plain_header), so it's read here.
    complete: bool = True
    gzipped: bool = False

    @property
    def format_name(self) -> str:
        return _FORMAT_NAMES.get(self.format, f"unknown({self.format})")

    @property
    def server_major(self) -> str:
        """The major version as Postgres names its images: '16', '9.6'."""
        return major_of(self.server_version)


def major_of(version: str | None) -> str:
    """'16.15 (Debian ...)' -> '16'.  '9.6.24' -> '9.6'."""
    if not version:
        raise ArchiveError("archive header carries no server version")
    match = re.match(r"\s*(\d+)(?:\.(\d+))?", version)
    if not match:
        raise ArchiveError(f"unparseable server version {version!r}")
    first = int(match.group(1))
    # Postgres switched to a single-number major at 10. Before that the major
    # was two components, and 9.6 images are still named "9.6".
    if first < 10:
        if match.group(2) is None:
            raise ArchiveError(f"unparseable pre-10 server version {version!r}")
        return f"{first}.{int(match.group(2))}"
    return str(first)


class _Reader:
    """A cursor that refuses to read past the end of what it was given.

    A truncated dump is the fixture this whole project exists for, so running
    off the end has to raise something specific rather than an IndexError that
    a caller might mistake for a bug in firedrill.
    """

    def __init__(self, data: bytes, int_size: int = 4):
        self.data = data
        self.pos = 0
        self.int_size = int_size

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ArchiveError(
                f"archive ends mid-header: wanted {n} bytes at offset {self.pos}, "
                f"only {len(self.data) - self.pos} remain"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def integer(self) -> int:
        sign = self.byte()
        value = 0
        for shift in range(self.int_size):
            value += self.byte() << (shift * 8)
        return -value if sign else value

    def string(self) -> str | None:
        length = self.integer()
        if length < 0:
            return None
        # A corrupt length is how a damaged header most often presents. Bound it
        # against what is actually left rather than trusting the file.
        if length > len(self.data) - self.pos:
            raise ArchiveError(
                f"archive declares a {length}-byte string at offset {self.pos} "
                f"but only {len(self.data) - self.pos} bytes remain"
            )
        return self.take(length).decode("utf-8", errors="replace")


def parse_header(data: bytes) -> ArchiveHeader:
    """Parse a custom-format header from the leading bytes of an archive."""
    if len(data) < len(MAGIC):
        raise ArchiveError("file is too short to be a pg_dump archive")
    if not data.startswith(MAGIC):
        raise ArchiveError(
            "not a pg_dump custom-format archive: missing the PGDMP magic. "
            "A plain-SQL dump or a gzipped file will look like this."
        )

    reader = _Reader(data)
    reader.take(len(MAGIC))
    vmaj, vmin, vrev = reader.byte(), reader.byte(), reader.byte()
    int_size = reader.byte()
    offset_size = reader.byte()
    fmt = reader.byte()

    if int_size < 1 or int_size > 8:
        raise ArchiveError(f"implausible integer size {int_size} in archive header")
    reader.int_size = int_size

    if (vmaj, vmin) >= _COMPRESSION_IS_BYTE_FROM:
        compression = reader.byte()
    else:
        compression = reader.integer()

    for _ in range(7):  # sec, min, hour, mday, mon, year, isdst
        reader.integer()

    dbname = reader.string()
    server_version = reader.string()
    pgdump_version = reader.string()

    return ArchiveHeader(
        archive_version=(vmaj, vmin, vrev),
        int_size=int_size,
        offset_size=offset_size,
        format=fmt,
        compression=compression,
        dbname=dbname,
        server_version=server_version,
        pgdump_version=pgdump_version,
    )


# The header is small and bounded; reading a fixed prefix keeps a 2 TB dump from
# being pulled into memory to learn its version number.
HEADER_BYTES = 512


# Directory (-Fd) and tar (-Ft) dumps both keep their table of contents in a
# member called toc.dat, and that file begins with the same PGDMP header as a
# custom archive. So the version can be read out of all three without a
# PostgreSQL client, which is what the version-matching depends on.
TOC = "toc.dat"


def read_header(path: str | pathlib.Path) -> ArchiveHeader:
    """The header, from a custom archive, a directory dump, or a tar dump."""
    path = pathlib.Path(path)
    if not path.exists():
        raise ArchiveError(f"no such file: {path}")

    if path.is_dir():
        toc = path / TOC
        if not toc.exists():
            raise ArchiveError(
                f"{path} is a directory with no {TOC} in it, so it is not a "
                "directory-format dump. `pg_dump -Fd -f <dir>` produces one."
            )
        with toc.open("rb") as handle:
            return parse_header(handle.read(HEADER_BYTES))

    if path.stat().st_size == 0:
        raise ArchiveError(f"{path} is empty (0 bytes)")

    with path.open("rb") as handle:
        head = handle.read(HEADER_BYTES)

    # Before the tar check: tarfile.is_tarfile() also tries gzip-compressed
    # tar, and on a truncated .gz it raised EOFError straight out of here.
    if head.startswith(GZIP_MAGIC) or _looks_plain(head):
        return read_plain_header(path)

    # A tar archive announces itself 257 bytes in, not at the start, so this is
    # checked only after the PGDMP magic has failed to match.
    if not head.startswith(MAGIC) and tarfile.is_tarfile(path):
        try:
            with tarfile.open(path) as tar:
                member = tar.extractfile(TOC)
                if member is None:
                    raise KeyError(TOC)
                return parse_header(member.read(HEADER_BYTES))
        except (KeyError, tarfile.TarError) as exc:
            raise ArchiveError(
                f"{path} is a tar file with no readable {TOC}, so it is not a "
                f"tar-format dump ({exc})."
            ) from None

    return parse_header(head)


GZIP_MAGIC = b"\x1f\x8b"
PLAIN_MARK = "-- PostgreSQL database dump"
PLAIN_TRAILER = "-- PostgreSQL database dump complete"
_DUMPED_FROM = re.compile(r"^-- Dumped from database version (.+?)\s*$", re.M)
_DUMPED_BY = re.compile(r"^-- Dumped by pg_dump version (.+?)\s*$", re.M)


def _looks_plain(head: bytes) -> bool:
    return PLAIN_MARK.encode() in head[:4096]


def read_plain_header(path: str | pathlib.Path) -> ArchiveHeader:
    """A plain-SQL dump (`pg_dump -Fp`, or `pg_dump db > backup.sql`),
    optionally gzipped.

    The server version comes from the comment pg_dump writes at the top of
    every plain dump: `-- Dumped from database version 16.15 (...)`. It's a
    comment, so it can be edited or stripped; when it's missing,
    server_version is None and the run needs an explicit --postgres rather
    than a guess.

    Completeness matters more here than for an archive. Measured on
    PostgreSQL 16: psql restoring a plain dump cut off mid-COPY exits 0 with
    no error at all, and the table comes back with 9,710 of its 20,000 rows
    -- it takes end-of-file as the end of the data. The only trace of the
    truncation is in the file: pg_dump always ends a plain dump with
    `-- PostgreSQL database dump complete`. No trailer, not complete.
    """
    path = pathlib.Path(path)
    with path.open("rb") as handle:
        gzipped = handle.read(2) == GZIP_MAGIC
    opener = (lambda: gzip.open(path, "rt", encoding="utf-8", errors="replace")) if gzipped \
        else (lambda: path.open("r", encoding="utf-8", errors="replace"))

    if gzipped:
        # zlib rather than gzip.open: gzip raises EOFError on a stream cut off
        # early and throws away what it had decoded, but a gzip cut off
        # inside its first 64 KB is still a truncated dump, not garbage.
        with path.open("rb") as raw:
            try:
                head = zlib.decompressobj(wbits=31).decompress(raw.read(1 << 20), 65536)
            except zlib.error as exc:
                raise ArchiveError(f"{path} is gzipped but could not be read ({exc})") from None
        head = head.decode("utf-8", errors="replace")
    else:
        with opener() as text:
            head = text.read(65536)
    if PLAIN_MARK not in head[:4096]:
        raise ArchiveError(
            f"{path} is not a pg_dump archive (no PGDMP header) and not a plain-SQL "
            "pg_dump either (no '-- PostgreSQL database dump' comment at the top). "
            + ("It is gzipped: check what was compressed." if gzipped else
               "A plain-SQL dump or a gzipped file will look like this.")
        )

    complete = True
    try:
        if gzipped:
            # ponytail: streams the whole file to see its end; a gzip stream
            # can't seek. A cut-off gzip raises EOFError: that's a truncated
            # dump, not an unreadable one.
            tail = ""
            with opener() as text:
                for chunk in iter(lambda: text.read(1 << 20), ""):
                    tail = (tail + chunk)[-4096:]
        else:
            with path.open("rb") as raw:
                raw.seek(max(0, path.stat().st_size - 4096))
                tail = raw.read().decode("utf-8", errors="replace")
        complete = PLAIN_TRAILER in tail
    except EOFError:
        complete = False

    server = _DUMPED_FROM.search(head)
    by = _DUMPED_BY.search(head)
    return ArchiveHeader(
        archive_version=(0, 0, 0), int_size=0, offset_size=0, format=FORMAT_PLAIN,
        compression=1 if gzipped else 0, dbname=None,
        server_version=server.group(1) if server else None,
        pgdump_version=by.group(1) if by else None,
        complete=complete, gzipped=gzipped,
    )
