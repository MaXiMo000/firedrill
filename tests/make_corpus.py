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

    def __init__(self, major: str):
        self.major = major
        self.name = f"firedrill-corpus-{major}-{uuid.uuid4().hex[:8]}"

    def __enter__(self):
        sh("docker", "run", "-d", "--name", self.name,
           "--label", "firedrill=1",
           "-e", "POSTGRES_PASSWORD=corpus-only-not-a-secret",
           f"postgres:{self.major}")
        deadline = time.time() + 120
        while time.time() < deadline:
            probe = sh("docker", "exec", "-u", "postgres", self.name,
                       "pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-q",
                       check=False)
            if probe.returncode == 0:
                return self
            time.sleep(0.3)
        raise RuntimeError(f"postgres:{self.major} never became ready")

    def __exit__(self, *exc):
        sh("docker", "rm", "-f", "-v", self.name, check=False)

    def psql(self, sql: str, db: str = "postgres"):
        return sh("docker", "exec", "-u", "postgres", self.name,
                  "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-c", sql)

    def dump(self, dest: pathlib.Path, db: str = "postgres", plain: bool = False):
        fmt = "-Fp" if plain else "-Fc"
        inside = "/tmp/out.dump"
        sh("docker", "exec", "-u", "postgres", self.name,
           "pg_dump", "-U", "postgres", fmt, "-f", inside, db)
        sh("docker", "cp", f"{self.name}:{inside}", str(dest))
        return dest


def _variant(src: "Source", dest: pathlib.Path, dbname: str, mutation: str):
    """The healthy schema in its own database, broken in exactly one way.

    Built from the same SCHEMA/SEED/INDEX as healthy rather than cloned with
    `template postgres`, which cannot run while we are connected to postgres.
    """
    src.psql(f"create database {dbname};")
    for statement in (SCHEMA, SEED, INDEX, mutation):
        src.psql(statement, db=dbname)
    return src.dump(dest, db=dbname)


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

    # -- empty file: zero bytes, which is what a full disk leaves behind.
    empty = outdir / "empty_file.dump"
    empty.write_bytes(b"")
    made["empty_file"] = empty

    return made


# Deferred to the phase that adds the check which reads them:
#   missing_extension   -> target image with the extension's control file removed
#   collation_mismatch  -> source and target on different libc
# Both need a purpose-built target image rather than a purpose-built dump, so
# they arrive with the check that reads them rather than sitting here unread.
#
# wrong_major_version needs no fixture: healthy_pg18 restored into a pinned 16
# container is the case, and drill.run(pin_major=...) already expresses it.


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
