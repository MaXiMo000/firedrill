# firedrill

**You don't have backups. You have hopes.**

firedrill takes a Postgres backup and *actually restores it* into a disposable,
version-matched container, then reports whether it worked and how long each
stage took. It is built to fail your build the day a backup stops being
restorable — not the day you need it.

> A verification that could not run never reports as passing.

**<https://maximo000.github.io/firedrill/>** — what it checks, and the measurements behind each check.

That rule is the whole design. No Docker, an unreadable archive, a container
that never came up — every one of those produces **COULD NOT VERIFY** and a
non-zero exit, never a green tick. A backup tool that says "OK" because it
silently skipped the restore is worse than no tool, because it manufactures
confidence.

## Status

**Phases 0–4.** Fetch (local, presigned URL, or S3, checksum-verified),
restore into an ephemeral version-matched container, then the ladder:
structure, volume, semantics, integrity. Three tiers, JUnit and JSON output,
a history file that turns RTO into a measured trend, a GitHub Action, and
point-in-time recovery. See `PLAN.md` for what is deliberately not built.

What works today:

```
$ firedrill run backups/production-2026-08-23.dump

firedrill  backups/production-2026-08-23.dump
  archive   custom v1.15.0  13.3KB  from 'postgres'
  source    PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2)  -> restored into postgres:16

  [ok  ] inspect     0.00s  16.15 (Debian 16.15-1.pgdg13+2) (custom)
  [ok  ] target      0.83s  postgres:16
  [ok  ] restore     0.09s  exit 0
  [ok  ] smoke       0.15s  1 user table(s)

  total     1.42s

  PASS -- restored and answered queries.
```

And when it isn't fine:

```
  [ok  ] inspect     0.00s  16.15 (Debian 16.15-1.pgdg13+2) (custom)
  [ok  ] target      0.83s  postgres:16
  [FAIL] restore     0.09s  exit 1
  [ok  ] smoke       0.16s  1 user table(s)

  1 finding(s):
    CRITICAL ARCHIVE_TRUNCATED    could not read from input file: end of file
             The archive is incomplete. The backup job most likely ran out of
             disk or was killed. Check the writer's exit status and free space
             at write time -- pg_dump can exit 0 having written a short file.

  FAIL -- the restore ran and produced findings above.
```

Note the schema restored and the table exists. Only the rows are missing. That
is what a truncated backup looks like from the outside.

## Install

```bash
pip install firedrill
```

Python 3.10+, and a working Docker. No Postgres client is required on the host —
the archive header is parsed in pure Python and every database operation happens
inside the target container, which is also what makes the version matching real.

## Use

```bash
firedrill run path/to/dump.dump            # restore and report
firedrill run dump.dump --json report.json # machine-readable
firedrill run dump.dump --rto 45m          # exceeding the budget is a finding
firedrill run dump.dump --tier fast        # schema only, for every commit
firedrill clean                            # remove containers left by a crash
```

Exit code is `0` only when the restore genuinely ran and produced no finding at
or above `--fail-on` (default `high`).

## Where the backup lives

A path works, and so does the place the backup actually sits:

```yaml
version: 1
source:
  type: s3
  bucket: acme-backups
  prefix: postgres/daily/
  select: newest          # or an explicit `key:`
  sha256: "007168050a7570c6a9c93230992de425f81316bf688ceb277546e45265aae9d5"
```

`type: local` (a path), `type: https` (a presigned URL — S3, GCS and Azure all
issue them), and `type: s3` (`pip install firedrill[s3]`). Give a `sha256:` or
a `size:` and the artefact is checked against it **before** anything tries to
restore it: a dump that arrives truncated but plausible never reaches a
container, and the run reports rather than passes. Quote the digest — YAML
reads a bare all-digit value as a number.

Three properties worth stating plainly:

- **Read-only by construction.** `sources.py` contains no verb that writes,
  deletes, copies or tags anything at the origin. "Never writes to the source"
  is a property of the file, not a promise in a README.
- **Credentials from the environment only.** There is no `--access-key` and no
  place for one in `firedrill.yml`, because `/proc/*/cmdline` is world-readable
  and CI logs echo command lines. boto3's default chain already does the right
  thing.
- **A presigned URL's signature is a credential**, so it is stripped from
  every report, log line and finding, and plain `http` to a non-local host is
  refused outright rather than putting a working one on the wire.

## Which dump formats

| format | flag | supported |
|---|---|---|
| custom | `-Fc` | yes |
| directory | `-Fd` | yes — the one that restores in parallel, so the one large databases use |
| tar | `-Ft` | yes |
| plain SQL | `-Fp` | **no**, and it cannot be |

Custom, directory and tar all carry a `PGDMP` header — directory and tar keep
theirs in a `toc.dat` member — so the major version is read out of the artefact
itself, with no PostgreSQL client on the host. That is what makes the
version-matching real.

Plain SQL has no header. Nothing in a `.sql` file states which server produced
it in a form worth trusting, so firedrill cannot pick a matching container and
says so rather than guessing at one.

## Which PostgreSQL versions

Tested end to end against **13, 14, 15, 16, 17 and 18** — dump on any of them,
restored into a container of that same major, read out of the archive header.
Archive formats 1.14 (13–15), 1.15 (16) and 1.16 (17–18) each have a committed
header fixture, so the parser stays covered even where containers cannot run.

One honest limit: `datcollversion` arrived in PostgreSQL 15, so on 13 and 14 no
collation version exists to compare. firedrill reports `COLLATION_UNVERIFIABLE`
there rather than pretending — nothing, not this tool and not PostgreSQL, can
tell you whether text indexes on those servers sort like production's.

A structure reference is portable across all six: taken on 14, it is clean
against a restore on 18. Upgrading Postgres must not turn every check red,
because that is how a team learns to ignore the tool.

## Tiers: how much to restore

A 2 TB restore cannot run on every commit.

| tier | restores | what does NOT run |
|---|---|---|
| `full` | everything | — |
| `fast` | schema only | row counts, smoke queries, sequence checks |
| `sample` | schema + rows for named tables | smoke queries, sequence checks |

```yaml
version: 1
tier: sample
sample:
  tables: [orders, customer]
```

The report always says which tier ran, in capitals when it is not `full`, and
a partial pass gets its own sentence — `PASS (fast tier) — the schema
restored. Whether the DATA is there was not checked.` A pass from a
schema-only run must never look like a pass from a full one.

The rungs a tier cannot honour report **NOT RUN**, never a tick, and the
config refuses combinations that would produce a misleading finding rather
than running them: `tier: sample` with a `volume` rule on an unsampled table,
or with `semantics` at all — a smoke query is arbitrary SQL, so there is no
knowing whether it reads a table whose rows came back.

## The ladder, and `firedrill.yml`

A bare `firedrill run` proves the backup restores and answers queries. To prove
it restored *the right data*, put a `firedrill.yml` next to it — it is picked up
automatically, or named with `--config`.

```yaml
version: 1

rto_budget: 45m

structure:
  reference: schema/production.txt   # committed, reviewable, diffable

volume:
  tables:
    orders: {min_rows: 1}

semantics:
  - name: recent orders exist
    sql: SELECT count(*) FROM orders WHERE created_at > now() - interval '7 days'
    expect: "> 0"

ignore:
  - check: COLLATION_UNVERIFIABLE
    reason: "restoring on alpine in CI; tracked in DR-114"
```

Generate the structure reference once and commit it:

```bash
firedrill run dump.dump --write-reference schema/production.txt
```

It is one line per catalog object, sorted, so a schema change shows up as a
readable diff in review rather than a wall of `pg_dump` output.

Three things the loader does that are worth knowing, because each one is a
failure it refuses to let pass quietly:

- **An unknown key is an error, not a warning.** A typo'd `tolerence:` that
  loaded silently would mean a check you believe is running is not running,
  and the run would still go green.
- **Every `ignore` needs a written reason.** An unexplained suppression is a
  config error. It is the only process this tool imposes, and it is what keeps
  a green run meaningful.
- **`expect` must be a comparison against a number.** There is deliberately no
  way to write a check whose result is printed, so a smoke query returns a
  shape and never a row.

Rungs that nothing configured report `n/a` — *not configured* — rather than a
tick. "Nothing asked for this" and "this passed" are different facts.

## What it checks today

| Rule | Meaning |
|---|---|
| `ARCHIVE_UNREADABLE` | the header will not parse — truncated, empty, or not a custom-format dump |
| `ARCHIVE_TRUNCATED` | the restore hit end-of-file partway through |
| `ROLE_ABSENT` | `OWNER TO` names a role that does not exist on the target |
| `EXTENSION_ABSENT` | an extension's binaries are missing from the restore image |
| `RESTORE_ERROR` / `RESTORE_WARNING` | anything else `pg_restore` said |
| `RESTORE_FAILED` | non-zero exit with nothing classifiable — never treated as success |
| `EXIT_CODE_LIED` | exit 0 with errors on stderr |
| `EMPTY_RESTORE` | restored cleanly and contains no user tables |
| `TARGET_UNAVAILABLE` | the restore could not be attempted |
| `RTO_EXCEEDED` | slower than the stated budget |
| `FETCH_FAILED` | the artefact could not be obtained, or is not the bytes that were claimed |
| `SOURCE_AMBIGUOUS` | a path *and* a configured source — which backup did you mean? |
| `VOLUME_DRIFT` | a table lost more rows than the tolerance allows, against the last known-good run |
| `SEQUENCE_UNCHECKED` | the database has sequences and none could be tied to a column, so none were checked |
| `PITR_TARGET_UNREACHED` | the WAL archive ends before the moment you asked to recover to |
| `PITR_UNASSERTED` | recovery reached the target and nothing checked what the database then held |
| `VERSION_MISMATCH` | `--postgres` pinned a major the archive did not come from |
| `STRUCTURE_MISSING` | an object in the committed reference did not come back |
| `STRUCTURE_UNEXPECTED` | the database has drifted from the reference |
| `VOLUME_BELOW_MINIMUM` | a table restored with fewer rows than the config requires |
| `VOLUME_TABLE_MISSING` | the config expects a table the restore does not have |
| `SEMANTICS_FAILED` | a smoke query restored cleanly and answered the wrong thing |
| `SEQUENCE_BEHIND` | a sequence is below `max(id)`; the first insert will collide |
| `COLLATION_MISMATCH` | the target's libc differs from the reference's — text indexes sort differently |
| `COLLATION_UNVERIFIABLE` | the target reports no collation version, so sort order cannot be checked at all |

Each of these is proved against a deliberately broken backup that `pg_restore`
itself is perfectly happy with — that is the point of the whole ladder — and
each is also asserted *not* to fire on a healthy one. A false positive costs
exactly what a false negative costs: a DR tool that cries wolf gets muted, and
a muted DR tool is worse than none because it still looks like coverage.

## A correction to the plan

`PLAN.md` §3.3 says a missing role or extension surfaces as a `pg_restore`
*warning* **with a zero exit code**. Measured on PostgreSQL 16 and 18 with
custom-format archives, that is not what happens: the exit code was `1` in every
broken case, accompanied by `warning: errors ignored on restore: N`.

The exit code is still not sufficient, for reasons that survive the correction:
it is one bit, so it says *something* broke but never *what*, and "role absent"
and "archive truncated" need different findings and different fixes. firedrill
therefore uses both signals and reports which one fired — with `EXIT_CODE_LIED`
kept as a guard, because the tool must not depend on that measurement staying
true in a future release.

## In CI, in ten lines

```yaml
- uses: MaXiMo000/firedrill@v0
  with:
    config: firedrill.yml
    rto: 45m
    history: firedrill-history.json
```

The action fails the build when the drill fails **and** when it could not run
at all — "we did not verify" must never be quieter than "we verified and it
was fine". It publishes the report before failing, so a red build is an
actionable one, and exposes `ok`, `verified`, `findings`, `seconds` and a
`summary` like `restored in 4m12s, 0 findings`.

Copy-paste templates live in [`examples/`](examples/): a nightly full drill
with read-only AWS credentials via OIDC, and a PR comment that runs the fast
tier and edits its own comment instead of posting a new one each push.

`--junit report.xml` writes JUnit XML so CI shows each rung separately. A rung
that could not run is `<skipped>`, never a silent pass, because most
dashboards colour those differently — which is exactly the distinction worth
preserving.

## Trends: RTO you have measured, not claimed

```bash
firedrill run dump.dump --history firedrill-history.json
```

Each run appends its durations, row counts and versions, and is measured
against the last known-good run *of the same tier*. The report then says
`19% slower than the last good full run (2.3s on 2026-08-24T…)`.

That history is also what makes `volume.tolerance` meaningful — a tolerance
needs something to be tolerant of:

```yaml
version: 1
volume:
  tolerance: 10%
  tables:
    audit_log: {tolerance: 50%}   # append-only, grows fast
```

Only a **drop** past the tolerance is a finding. Tables grow; a rule that
fired on growth would go off every week until somebody muted it, taking the
real findings with it.

The history file holds counts, durations and versions — aggregates and
catalog facts. It has no field that could hold a row, which is pinned by a
test, because it is the artefact of this tool most likely to be committed to
a repo by accident.

## Point-in-time recovery

A dump proves you can get *a* database back. PITR proves you can get it back to
a **chosen moment** — which is what you need after a `DELETE` without a `WHERE`
at 14:02. Almost nobody tests it, because testing it means performing it.

```bash
firedrill pitr \
  --base /backups/base --wal /backups/wal \
  --target '2026-08-25 14:01:00' --config firedrill.yml
```

The assertion has two halves, and it needs both:

```yaml
version: 1
semantics:
  - name: the row written before the target survived
    sql: select count(*) from events where label = 'before'
    expect: "== 1"
  - name: the row written after the target did not
    sql: select count(*) from events where label = 'after'
    expect: "== 0"
```

Restoring *everything* satisfies the first. Restoring *nothing* satisfies the
second. Only together do they say recovery stopped where it was told. Configure
neither and firedrill reports `PITR_UNASSERTED` rather than calling it a pass —
a server that came up proves a server came up.

Two things measured on PostgreSQL 16 that shaped this:

- An unreachable target does **not** silently promote. Recovery exits with
  `FATAL: recovery ended before configured recovery target was reached`, so
  "did it get there" needs no heuristic.
- `recovery_target_time` counts as reached only when a commit with a **later**
  timestamp exists in the WAL. A target after the final commit is *unreached*,
  not "satisfied at end of WAL".

## Prior art, honestly

| Thing | What it does | The gap |
|---|---|---|
| pgBackRest / WAL-G / Barman | take backups; `--check` validates archives | validates the *archive*, not a restored database |
| Cloud snapshot restore | restores | manual, unscheduled, unverified, unmeasured |
| `pg_verifybackup` | checksums a `pg_basebackup` | file integrity, not usability |
| Enterprise DR products | do this, well | expensive, closed, agent-based |
| Cron scripts | what most teams have | unversioned, unreported, silently rotted |

firedrill **never takes backups**. A tool that both takes and verifies its own
backups is grading its own homework.

## Safety

This tool restores databases, so the interlocks are the price of admission:

- It only ever uses a target it created itself. There is no code path that
  connects to a user-supplied DSN.
- The backup is bind-mounted **read-only**.
- No `--dsn` and no `--password` flags. The container password is generated per
  run, passed to Docker by variable *name* so it never enters argv, and never
  written to disk.
- No port is published; the target is unreachable from the host.
- Teardown runs in a `finally`, and `firedrill clean` removes anything a crash
  orphaned.

See `SECURITY.md` and `PLAN.md` §7.

## Development

```bash
python tests/make_corpus.py                       # build the broken-backup corpus
python tests/test_firedrill.py --require-integration
```

The corpus is generated from real containers, never hand-edited. Findings are
asserted in **both directions** — a false positive fails the build exactly as
hard as a false negative, because a DR tool that cries wolf gets muted, and a
muted DR tool still looks like coverage.

`--require-integration` makes a skipped container test a build failure. Without
it (Windows, where Linux containers cannot run) those tests skip *by name* and
the count is printed, so "it passed" and "it did not run" never look alike.

`python tests/field_test.py` restores pagila, chinook and northwind — real
databases this project did not write. Worth running after changing any check:
the corpus is synthetic, so it can only find the cases its author thought of.

### Cutting a release

```bash
# pyproject.toml is the single source of truth; release.yml fails if the
# tag and the declared version disagree.
python tests/test_firedrill.py --require-integration
git commit -am "Release vX.Y.Z" && git tag -a vX.Y.Z -m "firedrill vX.Y.Z"
git push origin main --follow-tags
git tag -f v0 vX.Y.Z && git push -f origin v0      # the moving major tag
```

The tag runs `verify` → `github-release` → `image` (GHCR, with provenance) →
`pypi` (Trusted Publishing over OIDC — there is no API token in this repo and
there must never be one). The `pypi` job waits for a reviewer, and a published
version number can never be reused, so let the gate do its job.

## Licence

MIT.
