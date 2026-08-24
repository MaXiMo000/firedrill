"""The Phase 1 rungs: volume, semantics, integrity.

Each is independently reportable and each distinguishes three outcomes, not
two: it passed, it failed, or it could not run. The third is the one that
matters. `drill.py` renders "not configured" and "not run" differently from
"ok", so a report can never show a green volume stage for a run where no
volume rule existed.

Kept flat, next to archive.py / docker.py / restore.py, because that is how
this package is already laid out. PLAN.md §5 sketches a stages/ package; four
functions of forty lines do not need six files and an __init__.

Every query here returns a count, a boolean or a catalog row -- never user
data (PLAN.md §7).
"""

from __future__ import annotations

from .finding import Finding

# psql -tA gives us unaligned, untitled output; this is the column separator.
SEP = "|"


def _rows(result) -> list[list[str]]:
    if result.returncode != 0:
        return []
    return [line.split(SEP) for line in result.stdout.strip().splitlines() if line]


def _quote(identifier: str) -> str:
    """`orders` -> "orders"; `public.orders` -> "public"."orders".

    config.py has already refused anything that is not a plain identifier, so
    this only has to add the quoting that makes a reserved word or a
    capitalised name work.
    """
    return ".".join(f'"{part}"' for part in identifier.split("."))


# ------------------------------------------------------------------ volume --

def volume(container, cfg, database: str) -> tuple[list[Finding], dict]:
    """Row counts against the minimums the config states.

    A table that lost 90% of its rows restores perfectly and passes every
    structural check, so this is the rung that catches it.
    """
    findings: list[Finding] = []
    counts: dict[str, int] = {}

    for table, rule in cfg.volume_tables.items():
        exists = container.sql(f"select to_regclass('{table}') is not null",
                               database=database)
        if exists.returncode != 0 or exists.stdout.strip() != "t":
            findings.append(Finding(
                stage="volume", rule="VOLUME_TABLE_MISSING", severity="high",
                message=f"the config expects a table {table!r}, and the restored "
                        "database does not have one",
                fix="Either the backup is of the wrong database, or the table was "
                    "dropped and the config was not updated. Both are worth "
                    "knowing; neither should pass quietly.",
                evidence="",
            ))
            continue

        counted = container.sql(f"select count(*) from {_quote(table)}",
                                database=database)
        if counted.returncode != 0:
            findings.append(Finding(
                stage="volume", rule="VOLUME_UNCOUNTABLE", severity="high",
                message=f"could not count rows in {table!r}",
                fix="The table exists in the catalog but would not answer a "
                    "count. Reported rather than skipped: an uncounted table has "
                    "not been checked.",
                evidence=(counted.stderr or "").strip(),
            ))
            continue

        count = int(counted.stdout.strip() or 0)
        counts[table] = count

        if rule.min_rows is not None and count < rule.min_rows:
            findings.append(Finding(
                stage="volume", rule="VOLUME_BELOW_MINIMUM", severity="high",
                message=f"{table} restored {count} row(s); the config requires at "
                        f"least {rule.min_rows}",
                fix="A table far below its expected size restored without any "
                    "error. Check whether the backup captured it mid-truncate, "
                    "or whether the dump was taken from the wrong database.",
                evidence="",
            ))

    return findings, {"counts": counts}


# --------------------------------------------------------------- semantics --

def semantics(container, cfg, database: str) -> tuple[list[Finding], dict]:
    """The user's own business-level questions.

    This is the rung that catches a stale replica: every structural check
    passes, the row counts are right, and the newest order is a week old.

    Each check is a single query returning a single number, compared against
    the operator and threshold the config states. The number is compared, not
    printed, so no row value can reach a report.
    """
    findings: list[Finding] = []
    results: dict[str, int] = {}

    for check in cfg.semantics:
        answer = container.sql(check.sql, database=database)
        if answer.returncode != 0:
            findings.append(Finding(
                stage="semantics", rule="SEMANTICS_UNRUNNABLE", severity="high",
                message=f"the check {check.name!r} could not run",
                fix="A check that errors has proved nothing. Fix the query or "
                    "remove it -- leaving it here means the report claims "
                    "coverage it does not have.",
                evidence=(answer.stderr or "").strip(),
            ))
            continue

        raw = answer.stdout.strip()
        try:
            value = int(raw.splitlines()[0]) if raw else 0
        except (ValueError, IndexError):
            findings.append(Finding(
                stage="semantics", rule="SEMANTICS_NOT_A_NUMBER", severity="high",
                message=f"the check {check.name!r} returned something that is not "
                        "a single number",
                fix="Write the query as a count or another single numeric value, "
                    "e.g. `select count(*) from ...`. The value is compared "
                    "against your `expect` and never printed.",
                evidence="",
            ))
            continue

        results[check.name] = value
        if not check.holds(value):
            findings.append(Finding(
                stage="semantics", rule="SEMANTICS_FAILED", severity="high",
                message=f"{check.name}: expected {check.expectation}, got {value}",
                fix="The database restored cleanly and does not contain what you "
                    "said it should. A dump of a replica that stopped "
                    "replicating looks exactly like this.",
                evidence="",
            ))

    return findings, {"results": results}


# --------------------------------------------------------------- integrity --

# Sequence and its owning column, for every serial/identity column in the
# database. Restored sequences are the classic post-failover landmine: the
# data is all there, and the first insert raises a duplicate key.
_SEQUENCES = """
select n.nspname, c.relname, tn.nspname, t.relname, a.attname
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join pg_depend d on d.objid = c.oid and d.classid = 'pg_class'::regclass
  and d.deptype in ('a', 'i')
join pg_class t on t.oid = d.refobjid
join pg_namespace tn on tn.oid = t.relnamespace
join pg_attribute a on a.attrelid = t.oid and a.attnum = d.refobjsubid
where c.relkind = 'S' and n.nspname not in ('pg_catalog', 'information_schema')
"""


def integrity(container, database: str) -> tuple[list[Finding], dict]:
    """The checks only a restore can make.

    Currently: every sequence is at or ahead of the maximum value in the
    column it feeds.

    Deliberately not here yet:

    * Orphaned foreign keys. A custom-format restore creates constraints after
      the data and validates them, so an orphan cannot survive the restore
      that this tool performs -- the check would cost a full scan per
      constraint to confirm something pg_restore already refused to let
      through. It arrives if and when a restore mode that can produce one does.
    * Collation version mismatch. It needs a target whose libc differs from
      the source's, which is a purpose-built image rather than a purpose-built
      dump. Shipping it unverified would mean a flagship check nobody has ever
      seen fire, which is the kind of confidence this project exists to refuse.
    """
    findings: list[Finding] = []
    checked = 0

    listing = container.sql(_SEQUENCES.strip().replace("\n", " "), database=database)
    if listing.returncode != 0:
        findings.append(Finding(
            stage="integrity", rule="INTEGRITY_UNRUNNABLE", severity="high",
            message="could not list sequences in the restored database",
            fix="The integrity rung did not run, so nothing it covers has been "
                "checked. This is reported rather than skipped.",
            evidence=(listing.stderr or "").strip(),
        ))
        return findings, {}

    for row in _rows(listing):
        if len(row) != 5:
            continue
        seq_schema, seq_name, tbl_schema, tbl_name, column = row
        sequence = f'"{seq_schema}"."{seq_name}"'
        table = f'"{tbl_schema}"."{tbl_name}"'
        probe = container.sql(
            f'select (select last_value from {sequence}), '
            f'coalesce((select max("{column}") from {table}), 0)',
            database=database,
        )
        rows = _rows(probe)
        if not rows or len(rows[0]) != 2:
            continue
        try:
            last_value, max_id = int(rows[0][0]), int(rows[0][1])
        except ValueError:
            continue

        checked += 1
        if last_value < max_id:
            findings.append(Finding(
                stage="integrity", rule="SEQUENCE_BEHIND", severity="high",
                message=f"sequence {seq_schema}.{seq_name} is at {last_value}, "
                        f"behind the largest {tbl_schema}.{tbl_name}.{column} "
                        f"of {max_id}",
                fix="The restore succeeded and the very first insert after "
                    "failover will raise a duplicate key. Run setval() past the "
                    "maximum before letting traffic in.",
                evidence="",
            ))

    return findings, {"sequences": checked}
