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
-- convalidated is part of the identity, not decoration. A CHECK or FOREIGN KEY
-- added NOT VALID exists in the catalog, is enforced for new rows only, and
-- was never checked against the rows already there. Measured: NOT VALID
-- survives a dump/restore intact, so a reference that says validated and a
-- restore that says otherwise is a real difference -- the restored database
-- enforces less than the reference claims, and looks identical doing it.
select 'constraint', n.nspname||'.'||c.relname||'.'||con.conname,
       con.contype::text || case when con.convalidated then '' else ' NOT VALID' end
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
-- Everything below was measured as missing: a database that lost its view,
-- function, trigger, RLS policy and enum type restored with a green structure
-- rung and exit 0, because the snapshot only knew about tables, indexes,
-- constraints, sequences and extensions.
--
-- The policy line is the one that matters most. A restore that drops an RLS
-- policy, or brings the table back with row security disabled, produces a
-- database that answers every query with rows it should never return -- and
-- nothing errors.
select 'view', n.nspname||'.'||c.relname,
       case c.relkind when 'm' then 'materialized' else 'view' end
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm')
  and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
-- Identity arguments, so an overload that vanished is not hidden by a
-- namesake that survived.
select 'routine', n.nspname||'.'||p.proname
         ||'('||pg_get_function_identity_arguments(p.oid)||')',
       p.prokind::text
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
  -- Objects owned by an extension are already represented by its version
  -- line; listing them makes the reference churn on every extension upgrade.
  and not exists (select 1 from pg_depend d
                  where d.objid = p.oid and d.deptype = 'e')
union all
select 'trigger', n.nspname||'.'||c.relname||'.'||t.tgname, ''
from pg_trigger t
join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
where not t.tgisinternal
  and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
select 'policy', n.nspname||'.'||c.relname||'.'||pol.polname,
       pol.polcmd::text || case when pol.polpermissive then ' permissive'
                                else ' restrictive' end
from pg_policy pol
join pg_class c on c.oid = pol.polrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
-- Whether row security is ON, separately from whether policies exist. A table
-- can come back with all its policies and RLS disabled, which is wide open.
select 'rowsecurity', n.nspname||'.'||c.relname,
       case when c.relrowsecurity then 'enabled' else 'disabled' end
         || case when c.relforcerowsecurity then ' forced' else '' end
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and c.relrowsecurity
  and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
union all
select 'type', n.nspname||'.'||t.typname, t.typtype::text
from pg_type t
join pg_namespace n on n.oid = t.typnamespace
where n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
  -- Enums and domains, plus standalone composites. Every table also creates a
  -- composite type; those are excluded, since the table is already listed.
  and (t.typtype in ('e', 'd')
       or (t.typtype = 'c' and exists (select 1 from pg_class c
                                       where c.oid = t.typrelid and c.relkind = 'c')))
  and not exists (select 1 from pg_depend d
                  where d.objid = t.oid and d.deptype = 'e')
union all
-- Carried in the reference so a later restore can be compared against the
-- libc that produced it. Excluded from the structure diff (see structure())
-- and read by collation() instead, because a sort-order change deserves its
-- own message rather than being one line of generic drift.
select 'collation', datcollate, {collation_detail}
from pg_database where datname = current_database()
order by 1, 2
"""

# datlocprovider and datcollversion arrived in PostgreSQL 15. Selecting them on
# 13 or 14 fails the WHOLE snapshot query -- measured: `--write-reference`
# returned STRUCTURE_UNREADABLE and wrote nothing, so the entire structure rung
# was unusable on two majors that are still widely deployed.
_COLLATION_SINCE_15 = "datlocprovider::text || ' ' || coalesce(datcollversion, '')"
_COLLATION_BEFORE_15 = "''"

# PostgreSQL 15.
_COLLVERSION_MIN = 150000


def server_version_num(container, database: str) -> int:
    """e.g. 160015. Zero when it cannot be read."""
    result = container.sql("select current_setting('server_version_num')",
                           database=database)
    try:
        return int(result.stdout.strip())
    except (ValueError, AttributeError):
        return 0

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
    detail = (_COLLATION_SINCE_15
              if server_version_num(container, database) >= _COLLVERSION_MIN
              else _COLLATION_BEFORE_15)
    result = container.sql(_SNAPSHOT.strip().format(collation_detail=detail),
                           database=database)
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
    if server_version_num(container, database) < _COLLVERSION_MIN:
        # Not a failure to read: there is genuinely nothing to read. Postgres
        # only began recording a collation version in 15, so on 13 and 14 no
        # tool can answer this question -- which is worth saying plainly rather
        # than reporting as if the query broke.
        collate = container.sql(
            "select datcollate from pg_database where datname = current_database()",
            database=database).stdout.strip()
        return [Finding(
            stage="integrity", rule="COLLATION_UNVERIFIABLE", severity="medium",
            message="this server predates collation version tracking (added in "
                    "PostgreSQL 15), so sort order cannot be verified here",
            fix="Nothing -- not this tool, not PostgreSQL -- can tell you "
                "whether text indexes on this target sort the way production's "
                "do. Compare the libc versions by hand, or restore on 15 or "
                "later where the server records it.",
            evidence="",
        )], {"collate": collate, "provider": "", "version": ""}

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

# A materialized view can exist and answer nothing -- the same shape as a
# constraint that exists and enforces nothing, and invisible in the same way.
#
# `relispopulated` is false both for a view created WITH NO DATA and for one
# whose REFRESH failed partway through the restore, and afterwards the two are
# indistinguishable. Measured on 16: pg_dump and pg_restore carry the flag
# across exactly, pg_restore exits 0 either way, and the restored object is
# byte-identical to a working one everywhere the structure rung looks -- the
# catalog entry, the definition and every column line come back the same. Only
# a query tells them apart:
#
#     select * from revenue_stale;
#     ERROR:  materialized view "revenue_stale" has not been populated
#
# So the whole ladder goes green over a database with an object that raises on
# first use. Deliberately not folded into _SNAPSHOT: `structure` compares
# reference and restore as sets of lines, so appending the state to the view
# line would make every committed reference report one MISSING and one
# UNEXPECTED per materialized view on the next run. This also catches it on a
# first run, where there is no reference to drift from.
_MATVIEWS_UNPOPULATED = """
select n.nspname||'.'||c.relname
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'm' and not c.relispopulated
  and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
order by 1
"""


def integrity(container, cfg, database: str,
              sequences: bool = True) -> tuple[list[Finding], dict]:
    """The checks only a restore can make.

    Currently: every sequence is at or ahead of the maximum value in the
    column it feeds, and no materialized view came back holding nothing.

    Deliberately not here yet:

    * Orphaned foreign keys. A custom-format restore creates constraints after
      the data and validates them, so an orphan cannot survive the restore
      that this tool performs -- the check would cost a full scan per
      constraint to confirm something pg_restore already refused to let
      through. It arrives if and when a restore mode that can produce one does.
    * amcheck. PLAN.md §2 lists it and it is not here, which is worth saying
      out loud rather than leaving as an absence. `bt_index_check` verifies
      B-tree structure, and the honest obstacle is verification: proving the
      check FIRES needs a genuinely corrupt index, which means manufacturing
      one by flipping bytes in a data file or by rebuilding under a changed
      collation. Until that fixture exists, shipping it would mean a check
      nobody has ever watched fail -- the same reason collation waited for a
      musl target rather than going out on reasoning alone.
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

    # Grouped by sequence, because one sequence can feed many columns -- every
    # partition of a partitioned table inherits the parent's DEFAULT. Measured
    # on the real pagila: 13 sequences produced 68 (sequence, column) pairs,
    # and counting pairs made the report say "68 of 13 sequence(s)", which is
    # visibly nonsense and was hiding a subtler error. Comparing per pair would
    # also emit the same finding once per partition.
    fed: dict[tuple, list] = {}
    for row in _rows(listing):
        if len(row) != 5:
            continue
        seq_schema, seq_name, tbl_schema, tbl_name, column = row
        fed.setdefault((seq_schema, seq_name), []).append((tbl_schema, tbl_name, column))

    for (seq_schema, seq_name), columns in sorted(fed.items()):
        sequence = f'"{seq_schema}"."{seq_name}"'
        # The high-water mark across every column this sequence feeds. A
        # sequence is only behind if it is behind the largest of them.
        highest = " union all ".join(
            f'select max("{col}") as v from "{sch}"."{tbl}"'
            for sch, tbl, col in columns)
        probe = container.sql(
            f'select (select last_value from {sequence}), '
            f'coalesce((select max(v) from ({highest}) x), 0)',
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
            where = ", ".join(f"{s}.{t}.{c}" for s, t, c in columns[:3])
            if len(columns) > 3:
                where += f" (+{len(columns) - 3} more)"
            findings.append(Finding(
                stage="integrity", rule="SEQUENCE_BEHIND", severity="high",
                message=f"sequence {seq_schema}.{seq_name} is at {last_value}, "
                        f"behind the largest value of {max_id} in {where}",
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

    stale = [row[0] for row in _rows(
        container.sql(_MATVIEWS_UNPOPULATED.strip(), database=database)) if row]
    if stale:
        findings.append(Finding(
            stage="integrity", rule="MATVIEW_UNPOPULATED", severity="medium",
            message=f"{len(stale)} materialized view(s) hold no data and raise "
                    "on any query",
            fix="A materialized view restores unpopulated when the source was "
                "unpopulated, and also when the REFRESH in the dump's post-data "
                "section failed -- pg_restore exits 0 either way and the object "
                "looks identical to a working one. Query one to see which you "
                "have: if the source is populated, the refresh failed and this "
                "restore is not usable; if it is not, the restore is faithful "
                "and the view was already answering nothing. Medium because "
                "only you can tell those apart.",
            evidence="\n".join(stale[:20]),
        ))

    return findings, {"sequences": checked, "sequences_present": total,
                      "matviews_unpopulated": len(stale), **collation_info}
