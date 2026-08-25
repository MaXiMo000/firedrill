"""Generate the corpus of deliberately broken backups.

Run: python tests/make_corpus.py [outdir]

Reproducible by construction: every fixture is built here from a real
PostgreSQL container, so nothing in the corpus is a hand-edited blob whose
provenance nobody remembers. Needs Docker; without it, it says so and exits
non-zero rather than producing an empty corpus that tests would then "pass"
against.

Phase 0 builds the fixtures Phase 0 can actually assert on. The remaining
PLAN.md §8 fixtures are listed at the bottom with the technique each needs --
a fixture with no check behind it is a silent skip wearing a costume, so they
arrive with the checks that read them.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import time
import uuid

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "corpus"
HEADERS_OUT = HERE / "headers"

# One widely-deployed major and the current one. Two is enough to catch
# pg_restore wording drift between releases, which is the thing the stderr
# parser must not be brittle about.
VERSIONS = ("16", "18")

# Committed 512-byte headers, so the pure-Python parser stays covered on a
# machine that cannot run Linux containers at all. 13 is here because it writes
# archive format 1.14, where compression is an Int rather than the single byte
# 1.15+ uses -- the branch whose comment says it is easy to get wrong was the
# one with no fixture behind it. 16 is 1.15, 18 is 1.16.
HEADER_VERSIONS = ("13", "16", "18")


# One schema, shared by the healthy fixture and every broken variant of it.
# The variants must differ from healthy in exactly one respect, or a test that
# claims to catch a stale replica might really be catching a schema difference.
SCHEMA = ("create table customer(id serial primary key, email text not null,"
          " created_at timestamptz default now());")
SEED = ("insert into customer(email)"
        " select 'user'||g||'@example.test' from generate_series(1,2000) g;")
INDEX = "create index on customer(email);"


def sh(*args, check=True, **kw):
    result = subprocess.run(args, capture_output=True, text=True, **kw)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{result.stderr}")
    return result


class Source:
    """A throwaway Postgres used only to produce dumps."""

    def __init__(self, major: str, flavour: str = ""):
        self.major = major
        self.flavour = flavour
        self.name = f"firedrill-corpus-{major}-{uuid.uuid4().hex[:8]}"

    def __enter__(self):
        sh("docker", "run", "-d", "--name", self.name,
           "--label", "firedrill=1",
           "-e", "POSTGRES_PASSWORD=corpus-only-not-a-secret",
           f"postgres:{self.major}{self.flavour}")
        deadline = time.time() + 120
        while time.time() < deadline:
            probe = sh("docker", "exec", "-u", "postgres", self.name,
                       "pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-q",
                       check=False)
            if probe.returncode == 0:
                return self
            time.sleep(0.3)
        raise RuntimeError(f"postgres:{self.major}{self.flavour} never became ready")

    def __exit__(self, *exc):
        sh("docker", "rm", "-f", "-v", self.name, check=False)

    def psql(self, sql: str, db: str = "postgres"):
        return sh("docker", "exec", "-u", "postgres", self.name,
                  "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-c", sql)

    def dump(self, dest: pathlib.Path, db: str = "postgres", plain: bool = False,
             fmt: str = ""):
        """`fmt` is a pg_dump format flag: -Fc (default), -Fd, -Ft, -Fp."""
        fmt = fmt or ("-Fp" if plain else "-Fc")
        inside = "/tmp/out.dump"
        sh("docker", "exec", "-u", "postgres", self.name, "rm", "-rf", inside)
        sh("docker", "exec", "-u", "postgres", self.name,
           "pg_dump", "-U", "postgres", fmt, "-f", inside, db)
        if dest.exists() and dest.is_dir():
            shutil.rmtree(dest)
        sh("docker", "cp", f"{self.name}:{inside}", str(dest))
        return dest


# Tagged into the postgres: namespace so that firedrill's own image_for()
# reaches it through the existing --image-flavour suffix, with no production
# code added for the benefit of a test. Upstream publishes no such tag, so
# there is nothing to shadow.
NOEXT_FLAVOUR = "-firedrill-noext"


def build_noext_image(major: str) -> str:
    """postgres:<major> with hstore's control file removed.

    The honest way to test EXTENSION_ABSENT: in a real recovery the binaries
    are missing from the host, and this is what that looks like.
    """
    tag = f"postgres:{major}{NOEXT_FLAVOUR}"
    dockerfile = (
        f"FROM postgres:{major}\n"
        "RUN rm -f /usr/share/postgresql/*/extension/hstore*\n"
    )
    proc = subprocess.run(
        ["docker", "build", "-t", tag, "-f", "-", "."],
        input=dockerfile, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"could not build {tag}\n{proc.stderr}")
    return tag


def _variant(src: "Source", dest: pathlib.Path, dbname: str, mutation: str):
    """The healthy schema in its own database, broken in exactly one way.

    Built from the same SCHEMA/SEED/INDEX as healthy rather than cloned with
    `template postgres`, which cannot run while we are connected to postgres.
    """
    src.psql(f"create database {dbname};")
    for statement in (SCHEMA, SEED, INDEX, mutation):
        src.psql(statement, db=dbname)
    return src.dump(dest, db=dbname)


def build_pitr(outdir: pathlib.Path) -> dict:
    """A base backup plus WAL, with a write timeline we know exactly.

    Order matters and is the whole fixture: the base backup is taken BEFORE the
    writes, so recovery has to replay WAL to see any of them. Then one row, a
    recorded timestamp, a gap, and a second row -- so that recovering to that
    timestamp must keep the first and drop the second. Either half alone is
    satisfiable by a broken restore.
    """
    base_out = outdir / "pitr" / "base"
    wal_out = outdir / "pitr" / "wal"
    for path in (base_out, wal_out):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)

    major = VERSIONS[0]
    name = f"firedrill-pitr-{uuid.uuid4().hex[:8]}"
    # The archive directory lives INSIDE the container and is copied out at the
    # end, exactly as the base backup is. A bind mount looked simpler and was
    # not portable: on Linux the host directory is owned by the runner user and
    # postgres inside the container is a different uid, so every archive_command
    # failed silently and the segment was never archived. macOS Docker Desktop
    # makes bind mounts world-writable, which is why it only broke in CI.
    sh("docker", "run", "-d", "--name", name, "--label", "firedrill=1",
       "-e", "POSTGRES_PASSWORD=corpus-only-not-a-secret",
       f"postgres:{major}",
       "-c", "wal_level=replica", "-c", "archive_mode=on",
       "-c", "archive_command=test ! -f /walarchive/%f && cp %p /walarchive/%f")
    try:
        # Inside the try, so a failure here still tears the container down.
        # Early archive attempts fail until this exists; the archiver retries,
        # which is why that is harmless.
        sh("docker", "exec", "-u", "root", name, "install", "-d", "-o", "postgres",
           "-g", "postgres", "-m", "700", "/walarchive")

        deadline = time.time() + 120
        while time.time() < deadline:
            if sh("docker", "exec", "-u", "postgres", name,
                  "pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-q",
                  check=False).returncode == 0:
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("pitr source never became ready")

        def psql(sql, tuples_only=False):
            flag = "-tAc" if tuples_only else "-c"
            return sh("docker", "exec", "-u", "postgres", name, "psql",
                      "-U", "postgres", "-v", "ON_ERROR_STOP=1", flag, sql)

        psql("create table events(id serial primary key, label text, "
             "at timestamptz default now());")
        # Base FIRST. A base taken after the writes would contain them already,
        # and the test would pass without replaying a single WAL record.
        sh("docker", "exec", "-u", "postgres", name,
           "pg_basebackup", "-U", "postgres", "-D", "/tmp/base", "-X", "stream",
           "-c", "fast")

        psql("insert into events(label) values ('before');")
        time.sleep(2)
        target = psql("select now() at time zone 'UTC'", tuples_only=True).stdout.strip()
        time.sleep(2)
        psql("insert into events(label) values ('after');")
        time.sleep(2)
        # A second target, AFTER both writes. Recovering to it must keep both
        # rows -- which is how the boundary assertion is shown to be capable of
        # failing. A check that cannot fail is decoration.
        late = psql("select now() at time zone 'UTC'", tuples_only=True).stdout.strip()
        time.sleep(2)
        # A third write, purely so `late` is reachable. Measured on PG 16:
        # recovery_target_time counts as REACHED only when a commit with a later
        # timestamp is found in the WAL. Without a commit after `late`, recovery
        # simply runs out of WAL and reports the target as unreached -- which is
        # a different failure from the one this fixture exists to demonstrate.
        psql("insert into events(label) values ('sentinel');")

        # Force the segment holding the writes into the archive, then WAIT FOR
        # IT. archive_command runs asynchronously, so a fixed sleep is a race:
        # it passed locally and failed on both CI runners, where the archiver
        # had not finished. WAL filenames sort in order, so comparing against
        # last_archived_wal is an exact condition rather than a guess at how
        # long a machine needs.
        # The name is taken BEFORE the switch, deliberately. pg_switch_wal()
        # returns the position at the END of the segment it completed, and
        # pg_walfile_name() of that lands on the segment that is now CURRENT --
        # which will not be archived until something switches again. Waiting on
        # it therefore waits forever: locally there happened to be a later
        # segment already archived so the comparison passed by luck, and CI
        # blocked on segment ...004 and raised.
        switched = psql("select pg_walfile_name(pg_current_wal_lsn())",
                        tuples_only=True).stdout.strip()
        psql("select pg_switch_wal();")
        psql("checkpoint;")
        deadline = time.time() + 120
        while time.time() < deadline:
            archived = psql("select coalesce(last_archived_wal, '') "
                            "from pg_stat_archiver", tuples_only=True).stdout.strip()
            if archived and archived >= switched:
                break
            time.sleep(0.5)
        else:
            stats = psql("select 'archived='||archived_count||' failed='||"
                         "failed_count||' last_failure='||"
                         "coalesce(last_failed_wal,'none')||' '||"
                         "coalesce(last_failed_time::text,'')",
                         tuples_only=True).stdout.strip()
            raise RuntimeError(
                f"WAL segment {switched} was never archived; the fixture would "
                f"have tested nothing. pg_stat_archiver: {stats}")

        sh("docker", "cp", f"{name}:/tmp/base/.", str(base_out))
        sh("docker", "cp", f"{name}:/walarchive/.", str(wal_out))
    finally:
        sh("docker", "rm", "-f", "-v", name, check=False)

    (outdir / "pitr" / "target.txt").write_text(target + "\n", encoding="utf-8")
    (outdir / "pitr" / "target_late.txt").write_text(late + "\n", encoding="utf-8")
    return {"base": base_out, "wal": wal_out, "target": target, "late": late}


def build(outdir: pathlib.Path = DEFAULT_OUT) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    HEADERS_OUT.mkdir(parents=True, exist_ok=True)
    made = {}

    for major in VERSIONS:
        with Source(major) as src:
            # -- healthy: the important one. Must produce zero findings.
            for statement in (SCHEMA, SEED, INDEX):
                src.psql(statement)
            healthy = src.dump(outdir / f"healthy_pg{major}.dump")
            made[f"healthy_pg{major}"] = healthy

            if major == VERSIONS[0]:
                # The same healthy database in the other two formats pg_restore
                # can read. Taken HERE, before missing_role adds a second table
                # to this same database -- the first attempt put them after it,
                # and "healthy_tar" quietly contained two tables and a missing
                # role. A fixture named healthy has to be healthy.
                made["healthy_dir"] = src.dump(outdir / "healthy_dir", fmt="-Fd")
                made["healthy_tar"] = src.dump(outdir / "healthy.tar", fmt="-Ft")

            # A committed 512-byte header, so the pure-Python parser can be
            # tested on a machine that cannot run Linux containers at all.
            (HEADERS_OUT / f"pg{major}.header").write_bytes(
                healthy.read_bytes()[:512]
            )

            if major == VERSIONS[0]:
                # -- missing_role: OWNER TO a role absent on the restore target.
                src.psql("create role appuser;")
                src.psql("create table owned(id int); alter table owned owner to appuser;")
                made["missing_role"] = src.dump(outdir / "missing_role.dump")

                # -- empty_database: restores perfectly, contains nothing. A dump
                # of the wrong database looks exactly like this.
                src.psql("create database empty_db;")
                made["empty_database"] = src.dump(
                    outdir / "empty_database.dump", db="empty_db"
                )

                # -- not_an_archive: a plain-SQL dump handed to a custom-format
                # reader. Common enough to deserve a clear message.
                made["not_an_archive"] = src.dump(
                    outdir / "not_an_archive.sql", plain=True
                )

                # -- volume_drop: the healthy schema with 99% of the rows gone.
                # Restores perfectly and passes every structural check. This is
                # what a dump of a partially-truncated table looks like.
                made["volume_drop"] = _variant(
                    src, outdir / "volume_drop.dump", "volume_drop",
                    "delete from customer where id > 20;",
                )

                # -- missing_index: the healthy schema with one index gone.
                # Right row count, right data, right sequences -- only the
                # catalog differs, so only the structure rung may fire.
                made["missing_index"] = _variant(
                    src, outdir / "missing_index.dump", "missing_index",
                    "drop index customer_email_idx;",
                )

                # -- stale_replica: the fixture that justifies the project.
                # Every structural check passes, the row counts are right, and
                # the newest row is a year old because the replica this was
                # dumped from stopped replicating.
                made["stale_replica"] = _variant(
                    src, outdir / "stale_replica.dump", "stale_replica",
                    "update customer set created_at = now() - interval '1 year';",
                )

                # -- sequence_behind: setval below max(id). Restores clean, and
                # the first insert after failover raises a duplicate key.
                made["sequence_behind"] = _variant(
                    src, outdir / "sequence_behind.dump", "sequence_behind",
                    "select setval('customer_id_seq', 5, true);",
                )

    # -- missing_extension: a dump that uses an extension the restore target
    # does not have. Measured first, and the cheap tricks did not work: the
    # alpine image *lists* plperl/plpython3u/pltcl in pg_available_extensions
    # but ships none of their runtime libraries, so they cannot be created on
    # either variant. Available is not loadable. So the target image really
    # does need its control file removed, which is what NOEXT_IMAGE is.
    build_noext_image(VERSIONS[0])
    with Source(VERSIONS[0]) as src:
        src.psql("create database missing_extension;")
        src.psql("create extension hstore;", db="missing_extension")
        src.psql("create table t(id int, attrs hstore);", db="missing_extension")
        made["missing_extension"] = src.dump(
            outdir / "missing_extension.dump", db="missing_extension"
        )

    # -- truncations, derived from the healthy dump at three depths. They land
    # in different stages on purpose: the header one never reaches a container,
    # the data one restores a schema with no rows in it.
    whole = made[f"healthy_pg{VERSIONS[0]}"].read_bytes()
    for label, size in (
        ("truncated_header", 40),
        ("truncated_toc", 260),
        ("truncated_data", int(len(whole) * 0.9)),
    ):
        path = outdir / f"{label}.dump"
        path.write_bytes(whole[:size])
        made[label] = path

    # Headers for majors the corpus does not otherwise build, so every archive
    # format version the parser understands has a committed fixture.
    for major in HEADER_VERSIONS:
        target = HEADERS_OUT / f"pg{major}.header"
        if target.exists():
            continue
        with Source(major) as src:
            src.psql(SCHEMA)
            probe = src.dump(outdir / f"_header_pg{major}.dump")
        target.write_bytes(probe.read_bytes()[:512])
        probe.unlink()

    # -- pitr is NOT built here. It needs its own server with archiving on,
    # and the test suite builds it on first use. Building it from both places
    # meant rmtree-ing and regenerating a fixture other tests had already read.

    # -- empty file: zero bytes, which is what a full disk leaves behind.
    empty = outdir / "empty_file.dump"
    empty.write_bytes(b"")
    made["empty_file"] = empty

    return made


# Everything PLAN.md §8 lists is now built, three of them without the
# purpose-built images that were assumed necessary:
#
#   collation_mismatch  -> no fixture needed. The alpine images are musl and
#                          the default Debian ones are glibc, so
#                          --image-flavour -alpine IS the differing target.
#   missing_extension   -> no control-file surgery needed. The alpine image
#                          ships the procedural languages (plperl, plpython3u,
#                          pltcl) and the Debian image does not, so a dump
#                          taken on alpine cannot restore into the default
#                          target. Built below.
#   wrong_major_version -> no fixture needed: healthy_pg18 restored into a
#                          pinned 16 container is the case, and
#                          drill.run(pin_major=...) already expresses it.


def main() -> int:
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    probe = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if probe.returncode != 0:
        print("docker is not available; cannot build the corpus.", file=sys.stderr)
        print("Refusing to write a partial corpus -- tests would pass against it.",
              file=sys.stderr)
        return 2
    made = build(out)
    for name, path in sorted(made.items()):
        print(f"  {name:<20} {path.stat().st_size:>9,} bytes  {path.name}")
    print(f"{len(made)} fixtures in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
