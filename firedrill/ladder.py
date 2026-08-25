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


# --------------------------------------------------------------- structure --

# One line per catalog object, sorted by the database so the snapshot is
# stable, reviewable and diffable in a pull request (PLAN.md §3.7 prefers a
# committed reference over a live production connection for exactly that
# reason). Deliberately not `pg_dump --schema-only`: that output is enormous,
# reorders itself between versions, and diffs badly.
_SNAPSHOT = """
select 'column', n.nspname||'.'||c.relname||'.'||a.attname,
       format_type(a.atttypid, a.atttypmod)
         || case when a.attnotnull then ' not null' else '' end
from pg_attribute a
join pg_class c on c.oid = a.attrelid
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p') and a.attnum > 0 and not a.attisdropped
  and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
select 'index', n.nspname||'.'||ic.relname, ''
from pg_index i
join pg_class ic on ic.oid = i.indexrelid
join pg_class c on c.oid = i.indrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
select 'constraint', n.nspname||'.'||c.relname||'.'||con.conname, con.contype::text
from pg_constraint con
join pg_class c on c.oid = con.conrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
  -- contype 'n' is excluded, measured against real 16 and 18 dumps: PG18
  -- materialises NOT NULL as pg_constraint rows and PG16 does not, so
  -- including them made every not-null column report as drift after a major
  -- upgrade. The fact is not lost -- the column line above already carries
  -- 'not null' -- so this removes a duplicate representation rather than a
  -- check, and keeps one reference usable across major versions.
  and con.contype <> 'n'
union all
select 'sequence', n.nspname||'.'||c.relname, ''
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'S' and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
select 'extension', extname, '' from pg_extension
union all
-- Carried in the reference so a later restore can be compared against the
-- libc that produced it. Excluded from the structure diff (see structure())
-- and read by collation() instead, because a sort-order change deserves its
-- own message rather than being one line of generic drift.
select 'collation', datcollate,
       datlocprovider::text || ' ' || coalesce(datcollversion, '')
from pg_database where datname = current_database()
order by 1, 2
"""

# Snapshot lines that structure() must not diff, because another rung owns
# them and reports them with the explanation they need.
_NOT_STRUCTURAL = ("collation|",)


def snapshot(container, database: str) -> str:
    """The restored database's catalog, as sorted reviewable text."""
    # Newlines are preserved. Collapsing them onto one line turns any
    # `--` comment in the SQL into one that swallows the rest of the
    # query -- which happened here, silently dropping whole branches
    # while still returning valid-looking rows. psql -c takes
    # multi-line SQL perfectly well.
    result = container.sql(_SNAPSHOT.strip(), database=database)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "catalog query failed")
    lines = [line for line in result.stdout.strip().splitlines() if line]
    return "\n".join(lines) + "\n"


def structure(container, cfg, database: str) -> tuple[list[Finding], dict]:
    """Diff the restored catalog against the committed reference.

    A missing object is high: something in the reference did not come back. An
    unexpected one is medium: the database has drifted from what the repo says
    it should be, which is worth knowing but is not the same as data loss.
    """
    reference = cfg.structure_reference
    try:
        expected = reference.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(
            stage="structure", rule="STRUCTURE_REFERENCE_UNREADABLE", severity="high",
            message=f"the structure reference {reference} could not be read: {exc}",
            fix="Point structure.reference at a snapshot written by "
                "`firedrill run --write-reference PATH`. A missing reference "
                "means the comparison did not happen, which is not a pass.",
            evidence="",
        )], {}

    try:
        actual = snapshot(container, database)
    except RuntimeError as exc:
        return [Finding(
            stage="structure", rule="STRUCTURE_UNREADABLE", severity="high",
            message="could not read the restored database's catalog",
            fix="The comparison did not run, so the schema has not been checked.",
            evidence=str(exc),
        )], {}

    def structural(text):
        return {line for line in text.splitlines()
                if line.strip() and not line.startswith(_NOT_STRUCTURAL)}

    want = structural(expected)
    have = structural(actual)

    findings: list[Finding] = []
    missing = sorted(want - have)
    unexpected = sorted(have - want)

    if missing:
        findings.append(Finding(
            stage="structure", rule="STRUCTURE_MISSING", severity="high",
            message=f"{len(missing)} object(s) in the reference are absent from "
                    "the restored database",
            fix="Something the schema snapshot says should exist did not come "
                "back. Check whether the dump excluded it, or whether the "
                "reference is out of date -- and update the reference in a "
                "reviewed commit, not by hand on the machine that failed.",
            evidence="\n".join(missing[:20]),
        ))
    if unexpected:
        findings.append(Finding(
            stage="structure", rule="STRUCTURE_UNEXPECTED", severity="medium",
            message=f"{len(unexpected)} object(s) exist in the restored database "
                    "and not in the reference",
            fix="The database has drifted from the committed snapshot. Usually a "
                "migration that landed without the reference being regenerated.",
            evidence="\n".join(unexpected[:20]),
        ))

    return findings, {"objects": len(have), "missing": len(missing),
                      "unexpected": len(unexpected)}


# ------------------------------------------------------------------ volume --

def volume(container, cfg, database: str,
           baseline: dict | None = None) -> tuple[list[Finding], dict]:
    """Row counts against the minimums the config states.

    A table that lost 90% of its rows restores perfectly and passes every
    structural check, so this is the rung that catches it.

    Only a DROP past the tolerance is a finding. Tables grow -- that is what
    tables do -- and a rule that fired on growth would go off every week until
    somebody muted it, taking the real findings with it.
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

        # Tolerance is measured against the last known-good run of the same
        # tier, which is what history.json is for.
        previous = (baseline or {}).get(table)
        tolerance = rule.tolerance if rule.tolerance is not None else cfg.volume_tolerance
        if previous and tolerance is not None and count < previous:
            lost = (previous - count) / previous
            if lost > tolerance:
                findings.append(Finding(
                    stage="volume", rule="VOLUME_DRIFT", severity="high",
                    message=f"{table} restored {count} row(s), down {lost * 100:.0f}% "
                            f"from {previous} in the last known-good run; the "
                            f"tolerance is {tolerance * 100:.0f}%",
                    fix="Rows that were in the last good restore are not in this "
                        "one. Either the source lost them or the backup did, and "
                        "both are worth knowing before the outage.",
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


# --------------------------------------------------------------- collation --

def _collation_line(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("collation|"):
            return line.strip()
    return ""


def collation(container, cfg, database: str) -> tuple[list[Finding], dict]:
    """PLAN.md §3.4, the silent one -- reported loudly because nothing else will.

    Two distinct facts, measured on real containers rather than assumed:

    * A musl target (`postgres:<n>-alpine`) reports an EMPTY collation
      version. Not a different one -- none at all. Text indexes built there
      have a sort order nothing can verify, so this reports "could not be
      verified" rather than passing. That is the honest answer and it is
      available without any reference at all.
    * A restore into a different libc than the reference recorded is a real
      mismatch. It needs a baseline, because a freshly restored database
      always agrees with the target it was created on -- the corruption is
      only visible against what production actually used.
    """
    findings: list[Finding] = []
    probe = container.sql(
        "select datcollate, datlocprovider, coalesce(datcollversion, '') "
        "from pg_database where datname = current_database()",
        database=database,
    )
    rows = _rows(probe)
    if not rows or len(rows[0]) != 3:
        return [Finding(
            stage="integrity", rule="COLLATION_UNREADABLE", severity="medium",
            message="could not read the restored database's collation settings",
            fix="The collation comparison did not run, so the one failure mode "
                "that produces wrong query results without any error has not "
                "been checked here.",
            evidence=(probe.stderr or "").strip(),
        )], {}

    collate, provider, version = rows[0]
    info = {"collate": collate, "provider": provider, "version": version}

    if not version:
        findings.append(Finding(
            stage="integrity", rule="COLLATION_UNVERIFIABLE", severity="medium",
            message=f"the restore target reports no collation version for "
                    f"{collate}, so sort order cannot be verified here",
            fix="A musl target (the -alpine images) records no collation "
                "version at all, so nothing -- not this tool, not PostgreSQL -- "
                "can tell you whether text indexes sort the way production's "
                "do. Restore into the default Debian image to get an answer "
                "instead of a shrug.",
            evidence="",
        ))

    reference = cfg.structure_reference
    if reference is not None:
        try:
            recorded = _collation_line(reference.read_text(encoding="utf-8"))
        except OSError:
            recorded = ""  # structure() already reports an unreadable reference
        current = f"collation|{collate}|{provider} {version}"
        if recorded and recorded != current:
            findings.append(Finding(
                stage="integrity", rule="COLLATION_MISMATCH", severity="high",
                message="the restore target's collation differs from the one the "
                        "reference was taken on",
                fix="Text indexes are built with this target's sort order. Where "
                    "it differs from production's, queries can return WRONG ROWS "
                    "against a database that looks perfectly healthy, and nothing "
                    "raises an error. Restore on a matching libc before trusting "
                    "any range or equality result over text.",
                evidence=f"reference: {recorded}\nrestored:  {current}",
            ))

    return findings, info


# --------------------------------------------------------------- integrity --

# Sequence and its owning column, for every serial/identity column in the
# database. Restored sequences are the classic post-failover landmine: the
# data is all there, and the first insert raises a duplicate key.
# Two ways a sequence can feed a column, and real databases use both.
#
# The first is ownership -- `serial`, or an explicit OWNED BY -- recorded in
# pg_depend. That is all this query used to match, and it was measured against
# pagila, a schema thousands of people use: the answer there is ZERO. Pagila
# links its 13 sequences purely through the column DEFAULT, with no OWNED BY
# anywhere, and `pg_get_serial_sequence` resolves none of them either. So the
# sequence check examined nothing and the run went green, which is exactly the
# failure this project exists to prevent.
#
# The second reads nextval() out of the default expression. UNION dedupes a
# column that has both.
_SEQUENCES = r"""
select n.nspname, c.relname, tn.nspname, t.relname, a.attname
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
join pg_depend d on d.objid = c.oid and d.classid = 'pg_class'::regclass
  and d.deptype in ('a', 'i')
join pg_class t on t.oid = d.refobjid
join pg_namespace tn on tn.oid = t.relnamespace
join pg_attribute a on a.attrelid = t.oid and a.attnum = d.refobjsubid
where c.relkind = 'S' and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union
select sn.nspname, s.relname, tn.nspname, t.relname, a.attname
from pg_attrdef ad
join pg_class t on t.oid = ad.adrelid
join pg_namespace tn on tn.oid = t.relnamespace
join pg_attribute a on a.attrelid = ad.adrelid and a.attnum = ad.adnum
  and not a.attisdropped
join pg_class s
  on s.oid = to_regclass(substring(pg_get_expr(ad.adbin, ad.adrelid)
                                   from 'nextval\(''([^'']+)'''))
join pg_namespace sn on sn.oid = s.relnamespace
where s.relkind = 'S' and tn.nspname !~ '^pg_' and tn.nspname <> 'information_schema'
"""

# How many sequences exist at all, so "checked none" can be told apart from
# "there are none". Only one of those is reassuring.
_SEQUENCE_COUNT = """
select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'S' and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
"""


def integrity(container, cfg, database: str,
              sequences: bool = True) -> tuple[list[Finding], dict]:
    """The checks only a restore can make.

    Currently: every sequence is at or ahead of the maximum value in the
    column it feeds.

    Deliberately not here yet:

    * Orphaned foreign keys. A custom-format restore creates constraints after
      the data and validates them, so an orphan cannot survive the restore
      that this tool performs -- the check would cost a full scan per
      constraint to confirm something pg_restore already refused to let
      through. It arrives if and when a restore mode that can produce one does.
    Collation now lives in collation() above and is called from here, so the
    caller still gets one integrity rung.
    """
    findings: list[Finding] = []
    checked = 0

    if not sequences:
        # A schema-only restore has no rows, so max(id) is 0 everywhere and
        # every sequence would look fine. Not asked is not the same as passed.
        collation_findings, collation_info = collation(container, cfg, database)
        return collation_findings, {"sequences": 0, **collation_info}

    listing = container.sql(_SEQUENCES.strip(), database=database)
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

    collation_findings, collation_info = collation(container, cfg, database)
    findings.extend(collation_findings)

    # "I checked zero sequences" and "there are zero sequences" are different
    # facts, and only one of them is reassuring. pagila made the difference
    # concrete: 13 sequences present, none reachable by the old query, and a
    # perfectly green report.
    present = container.sql(_SEQUENCE_COUNT.strip(), database=database)
    try:
        total = int(present.stdout.strip() or 0)
    except ValueError:
        total = 0
    if total and not checked:
        findings.append(Finding(
            stage="integrity", rule="SEQUENCE_UNCHECKED", severity="medium",
            message=f"the database has {total} sequence(s) and none could be "
                    "linked to a column, so none were checked",
            fix="firedrill finds a sequence's column through ownership or "
                "through the column's DEFAULT. This database uses neither, so "
                "the sequence check proved nothing here. Reported rather than "
                "left looking like a pass.",
            evidence="",
        ))

    return findings, {"sequences": checked, "sequences_present": total,
                      **collation_info}
