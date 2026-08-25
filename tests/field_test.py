"""Run firedrill against real databases it did not create.

    python tests/field_test.py

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
SOURCES = {
    "pagila": [
        "https://raw.githubusercontent.com/devrimgunduz/pagila/master/pagila-schema.sql",
        "https://raw.githubusercontent.com/devrimgunduz/pagila/master/pagila-data.sql",
    ],
    "chinook": [
        "https://raw.githubusercontent.com/lerocha/chinook-database/master/"
        "ChinookDatabase/DataSources/Chinook_PostgreSql.sql",
    ],
    "northwind": [
        "https://raw.githubusercontent.com/pthom/northwind_psql/master/northwind.sql",
    ],
}


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
    """Load each database into Postgres and dump it in custom format."""
    dumps = {}
    with make_corpus.Source(make_corpus.VERSIONS[0]) as src:
        subprocess.run(["docker", "exec", "-u", "root", src.name,
                        "install", "-d", "-o", "postgres", "-g", "postgres",
                        "/field"], capture_output=True)
        for name, urls in SOURCES.items():
            print(f"  {name}:")
            files = _download(urls, workdir)
            src.psql(f"create database {name};")
            for path in files:
                subprocess.run(["docker", "cp", str(path), f"{src.name}:/field/"],
                               capture_output=True)
                subprocess.run(
                    ["docker", "exec", "-u", "postgres", src.name, "psql",
                     "-U", "postgres", "-d", name, "-q", "-f", f"/field/{path.name}"],
                    capture_output=True, text=True)
            dumps[name] = src.dump(workdir / f"{name}.dump", db=name)
            print(f"    dumped {dumps[name].stat().st_size:,} bytes")
    return dumps


def main() -> int:
    usable, why = docker.docker_available()
    if not usable:
        print(f"docker is not usable: {why}", file=sys.stderr)
        return 2

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
