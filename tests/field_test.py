"""Run firedrill against real databases it did not create.

    python tests/field_test.py              # restore them, expect silence
    python tests/field_test.py --mutate     # break one thing at a time

The corpus in `make_corpus.py` is synthetic by construction. That is what makes
it precise -- each fixture is broken in exactly one way -- and it is also what
makes it a laboratory. Every schema in it was written by the same person who
wrote the checks, with the same habits, which means the corpus cannot find the
cases that person did not think of.

These databases were written by other people. The first run of this script
found a real bug in firedrill: pagila links all thirteen of its sequences
through the column DEFAULT rather than OWNED BY, and `pg_get_serial_sequence`
resolves none of them, so the SEQUENCE_BEHIND check examined nothing at all and
reported "0 sequence(s)" -- which reads like "fine". Fixed, and pinned by a
test in the suite; recorded here because the *method* is what found it.

Needs Docker and network access. Reports what it finds, including nothing.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from firedrill import drill, docker  # noqa: E402
import make_corpus  # noqa: E402

# Widely used, publicly published, and not written by us. pagila is the
# richest: views, functions, triggers, enums and full-text search.
# major: the version each schema actually needs. pagila's master uses uuidv7()
# and transaction_timeout, which are PG17/18 features -- on 16 it throws 323
# errors and loads 11 of its 70 tables, silently, leaving no film, rental,
# payment or customer. The first version of this script did exactly that and
# reported "0 load errors", because it grepped for "^ERROR" while psql prints
# "psql:file:line: ERROR:". A field test that quietly tests a third of a
# database is worse than no field test.
SOURCES = {
    "pagila": {
        "major": "18",
        "urls": [
            "https://raw.githubusercontent.com/devrimgunduz/pagila/master/pagila-schema.sql",
            "https://raw.githubusercontent.com/devrimgunduz/pagila/master/pagila-data.sql",
        ],
    },
    "chinook": {
        "major": "16",
        "urls": ["https://raw.githubusercontent.com/lerocha/chinook-database/master/"
                 "ChinookDatabase/DataSources/Chinook_PostgreSql.sql"],
    },
    "northwind": {
        "major": "16",
        "urls": ["https://raw.githubusercontent.com/pthom/northwind_psql/master/northwind.sql"],
    },
}

# Some noise is unavoidable -- pagila sets a few server parameters that differ
# by build. This is a ceiling on "noise", not a target; anything above it means
# the database did not really load and the run says so instead of testing a
# fragment.
MAX_LOAD_ERRORS = 20


def _download(urls, into: pathlib.Path) -> list[pathlib.Path]:
    paths = []
    for url in urls:
        dest = into / url.rsplit("/", 1)[-1]
        print(f"    fetching {dest.name} ...", end=" ", flush=True)
        urllib.request.urlopen(url, timeout=180)  # fail fast on a dead URL
        with urllib.request.urlopen(url, timeout=180) as response:
            dest.write_bytes(response.read())
        print(f"{dest.stat().st_size:,} bytes")
        paths.append(dest)
    return paths


def build_dumps(workdir: pathlib.Path) -> dict:
    """Load each database into Postgres and dump it in custom format.

    Raises if a load produced more than MAX_LOAD_ERRORS. Testing a database
    that only half arrived, and reporting the result as if it were whole, is
    the failure this project is about -- it does not become acceptable because
    it happens in the test harness.
    """
    dumps = {}
    by_major: dict[str, list] = {}
    for name, spec in SOURCES.items():
        by_major.setdefault(spec["major"], []).append(name)

    for major, names in sorted(by_major.items()):
        with make_corpus.Source(major) as src:
            subprocess.run(["docker", "exec", "-u", "root", src.name,
                            "install", "-d", "-o", "postgres", "-g", "postgres",
                            "/field"], capture_output=True)
            for name in names:
                print(f"  {name} (postgres:{major}):")
                files = _download(SOURCES[name]["urls"], workdir)
                src.psql(f"create database {name};")
                errors = 0
                for path in files:
                    subprocess.run(["docker", "cp", str(path), f"{src.name}:/field/"],
                                   capture_output=True)
                    result = subprocess.run(
                        ["docker", "exec", "-u", "postgres", src.name, "psql",
                         "-U", "postgres", "-d", name, "-q", "-f",
                         f"/field/{path.name}"],
                        capture_output=True, text=True)
                    # "ERROR:" anywhere, because psql prefixes it with the file
                    # and line. Anchoring to the start of the line is how the
                    # first version of this counted 323 errors as zero.
                    errors += sum(1 for line in result.stderr.splitlines()
                                  if "ERROR:" in line)
                tables = int(src.psql(
                    "select count(*) from pg_tables where schemaname='public'",
                    db=name).stdout.strip().splitlines()[2].strip())
                print(f"    {tables} tables, {errors} load errors")
                if errors > MAX_LOAD_ERRORS:
                    raise RuntimeError(
                        f"{name} did not load: {errors} errors on postgres:"
                        f"{major}. Restoring a fragment and calling it a field "
                        "test would prove nothing.")
                dumps[name] = src.dump(workdir / f"{name}.dump", db=name)
                print(f"    dumped {dumps[name].stat().st_size:,} bytes")
    return dumps


# Break a real schema in one way at a time, and check each break is caught.
# The synthetic corpus does this with a schema written by the same person as
# the checks; this does it to one written by strangers, with 70 tables, a
# partitioned table, triggers, views and full-text search.
MUTATIONS = {
    "drop_trigger":  "drop trigger film_fulltext_trigger on film;",
    "drop_function": "drop function last_updated() cascade;",
    "drop_view":     "drop view actor_info cascade;",
    "drop_index":    "drop index idx_title;",
    "drop_column":   "alter table film drop column description cascade;",
    "drop_not_null": "alter table film alter column title drop not null;",
    "empty_table":   "delete from payment;",
    "sequence_back": "select setval('film_film_id_seq', 3, true);",
    "backdate":      "update rental set rental_date = rental_date - interval '9 years';",
    "not_valid":     "alter table film add constraint chk_len check (length > 0) not valid;",
    "enable_rls":    "alter table film enable row level security;",
}

MUTATION_CONFIG = """
version: 1
structure:
  reference: {reference}
volume:
  tables:
    payment: {{min_rows: 1}}
    rental:  {{min_rows: 1000}}
semantics:
  - name: recent rentals exist
    sql: "select count(*) from rental where rental_date > now() - interval '8 years'"
    expect: "> 0"
"""


def mutate(workdir: pathlib.Path) -> int:
    """Every mutation must produce at least one finding. Silence is the bug."""
    from firedrill import config

    spec = SOURCES["pagila"]
    dumps = {}
    with make_corpus.Source(spec["major"]) as src:
        subprocess.run(["docker", "exec", "-u", "root", src.name, "install", "-d",
                        "-o", "postgres", "-g", "postgres", "/field"],
                       capture_output=True)
        files = _download(spec["urls"], workdir)
        src.psql("create database pagila;")
        for path in files:
            subprocess.run(["docker", "cp", str(path), f"{src.name}:/field/"],
                           capture_output=True)
            subprocess.run(["docker", "exec", "-u", "postgres", src.name, "psql",
                            "-U", "postgres", "-d", "pagila", "-q", "-f",
                            f"/field/{path.name}"], capture_output=True, text=True)

        # `template pagila` copies the files rather than replaying 13MB of SQL
        # per variant, so this stays minutes rather than an afternoon.
        for name, sql in {"healthy": None, **MUTATIONS}.items():
            src.psql(f"create database m_{name} template pagila;")
            if sql:
                try:
                    src.psql(sql, db=f"m_{name}")
                except RuntimeError as exc:
                    print(f"  {name}: could not apply -- "
                          f"{str(exc).splitlines()[-1][:70]}")
                    continue
            dumps[name] = src.dump(workdir / f"{name}.dump", db=f"m_{name}")

    reference = workdir / "pagila-reference.txt"
    drill.run(dumps["healthy"], write_reference=reference)
    cfg = config.loads(MUTATION_CONFIG.format(reference=reference))

    print(f"\n  {'mutation':15} {'exit':>4}  findings")
    print("  " + "-" * 70)
    missed = []
    for name, dump in dumps.items():
        report = drill.run(dump, cfg=cfg)
        rules = sorted({f.rule for f in report.findings})
        print(f"  {name:15} {report.exit_code:>4}  "
              f"{', '.join(rules) if rules else '(silent)'}")
        if name == "healthy":
            if rules:
                missed.append("healthy produced findings -- a false positive")
        elif not rules:
            missed.append(name)

    print()
    if missed:
        print("NOT CAUGHT:", ", ".join(missed))
        return 1
    print("Every mutation caught, and the unmutated original stayed silent.")
    return 0


def main() -> int:
    usable, why = docker.docker_available()
    if not usable:
        print(f"docker is not usable: {why}", file=sys.stderr)
        return 2

    if "--mutate" in sys.argv:
        with tempfile.TemporaryDirectory() as tmp:
            print("breaking a real schema one way at a time:")
            return mutate(pathlib.Path(tmp))

    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        print("building dumps from published databases:")
        dumps = build_dumps(workdir)

        print("\nrestoring each with firedrill:\n")
        surprises = 0
        for name, dump in sorted(dumps.items()):
            report = drill.run(dump)
            rules = [f.rule for f in report.findings]
            print(f"  {name:10} exit={report.exit_code}  "
                  f"tables={report.stage('smoke').detail:<18} "
                  f"integrity={report.stage('integrity').detail}")
            for finding in report.findings:
                surprises += 1
                print(f"      {finding.severity.upper():8} {finding.rule}: "
                      f"{finding.message}")

    print()
    if surprises:
        # Not necessarily a bug in the backup. On a database nobody has
        # deliberately broken, the first suspect is firedrill.
        print(f"{surprises} finding(s) on databases nobody broke on purpose.")
        print("Check whether each is real before assuming it is: a false "
              "positive here is a bug in this tool.")
        return 1
    print("No findings. Healthy databases restored silently, which is the "
          "half of the job that is easy to get wrong quietly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
