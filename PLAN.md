# firedrill — deep plan

Read `HANDOFF.md` first.

---

## 1. The problem, stated precisely

Every organisation with a database takes backups. Nearly all of them have never
restored one outside an emergency. The gap between those two facts is where
companies die.

The failure is never "we had no backup". It is always one of these, discovered
at the worst possible moment:

| What went wrong | Why nobody noticed |
|---|---|
| `pg_dump` exited 0 but the output was truncated by a full disk | exit code 0 |
| The dump was of the wrong database, or a replica that had stopped replicating | it ran nightly, without error |
| An extension (`postgis`, `pgvector`, `citext`) is absent on the restore host | never restored anywhere else |
| Roles referenced by `OWNER TO` do not exist on the target | `pg_restore` warns, does not fail |
| Backups have been encrypted with a key rotated six months ago | the encryption step kept succeeding |
| The glibc/ICU collation version differs, so restored text indexes are silently corrupt | queries return wrong rows, no error |
| Restore takes 14 hours; the stated RTO is 1 hour | never measured |
| Retention deleted the last good backup before anyone found the bad ones | the bad ones "succeeded" |

Every one of these is invisible to a backup *job* and obvious to a backup
*restore*. That is the entire product.

**One-line positioning:** *A backup you have not restored is not a backup. This
restores it, on a schedule, and tells you when it stops working.*

---

## 2. What it actually does

A ladder. Each rung is independently reportable, and a rung that cannot run
reports as unverified rather than passing.

1. **Fetch** — obtain the artefact (local path, S3, GCS, or a provider snapshot).
   Verify size and checksum against what the backup job claimed.
2. **Restore** — into a disposable Postgres of the correct major version.
   Capture `pg_restore` stderr; warnings are findings, not noise.
3. **Structure** — compare the restored catalog against a reference: tables,
   columns, types, constraints, indexes, sequences, extensions, roles.
4. **Volume** — row counts per table, against a tolerance or against the last
   known-good restore. A table that lost 90% of its rows restored "successfully".
5. **Semantics** — user-written smoke queries with expected shapes. *"There is
   at least one order from the last 7 days"* catches a stale-replica dump that
   every structural check passes.
6. **Integrity** — the checks that only a restore can make: sequence values
   ahead of `max(id)`, no orphaned foreign keys, collation version match,
   `amcheck` on critical indexes if available.
7. **Time** — how long every stage took, against a stated RTO budget.

Output: one report, a machine-readable JSON, and a non-zero exit when a rung
that matters failed.

---

## 3. The hard parts

This section exists because these are what make it a real engineering project
rather than a shell script, and a new chat should know them before designing.

### 3.1 Disposability is the whole safety model
The restore target must be created and destroyed by firedrill. A user-supplied
DSN is the dangerous path and needs interlocks (§7). An ephemeral container
solves safety *and* version matching in one move.

### 3.2 Major version matching
A dump from Postgres 16 will not restore into 14. The tool must read the
server version out of the dump header (`pg_restore --list` exposes it for custom
format) and start a container of that major version, rather than whatever is
lying around.

### 3.3 Extensions and roles
The two most common restore failures. `CREATE EXTENSION` fails if the binary is
absent from the image; `OWNER TO app_user` fails if the role does not exist.
Both surface as `pg_restore` *warnings* with a zero exit code in some modes —
which is precisely how a broken restore looks successful. Parse stderr; do not
trust the exit code alone.

### 3.4 Collation, the silent one
If the restore host's glibc or ICU differs from the source, text indexes are
built with a different sort order. No error is raised. Queries then return
*wrong results* against a database that looks perfectly healthy. Compare
`pg_collation.collversion` and the value recorded in `pg_database`; report a
mismatch loudly, because nothing else will.

### 3.5 Very large backups
A 2 TB restore cannot run on every commit. Tiers:
- **fast** — restore schema only (`--schema-only`), plus structural checks
- **sample** — schema plus a bounded subset of tables
- **full** — everything, on a schedule, with a generous timeout

Say which tier ran in the report. A "pass" from a schema-only run must never
look like a "pass" from a full one.

### 3.6 Point-in-time recovery
Beyond a dump: given a base backup plus WAL, restore to a target timestamp and
assert a row written before it exists and one written after it does not. This is
the check nobody does and the one that actually proves PITR works. Later phase,
but design so it fits.

### 3.7 Where the reference comes from
"Schema matches" needs something to match *against*. Options, in order:
1. A committed schema snapshot in the repo (best — reviewable, diffable)
2. A live read-only production connection (accurate, but needs prod access)
3. The previous successful restore (catches drift, not correctness)

---

## 4. Prior art, honestly

Check each of these before writing a line, and state the difference in the
README. If one is strictly better at something, say so.

| Thing | What it does | Expected gap |
|---|---|---|
| pgBackRest / WAL-G / Barman | take backups; `--check` validates archives | validate the *archive*, not a restored database |
| Cloud provider snapshot restore | restores | manual, unscheduled, unverified, unmeasured |
| `pg_verifybackup` | checksums a `pg_basebackup` | file integrity only, not usability |
| Enterprise DR products | do this, well | expensive, closed, agent-based |
| Hand-rolled cron scripts | what most teams have | unversioned, unreported, silently rotted |

The gap being filled: **an open-source CLI that proves restorability on a
schedule and fails a build when it stops being true.**

---

## 5. Technical architecture (Python)

Python because it is Ritish's language, `psycopg` is excellent, and every
interesting operation here is orchestration rather than computation.

```
firedrill/
  cli.py             argparse: run, verify, report, init
  config.py          firedrill.yml -> typed settings, refuses ambiguity
  finding.py         one Finding model, severities, stable ids
  sources/
    __init__.py      registry; each source yields a local artefact + metadata
    local.py         a path on disk
    s3.py            boto3, or plain HTTP for presigned URLs
    pgdump.py        understands custom/dir/tar/plain formats
    basebackup.py    pg_basebackup layouts, for PITR later
  targets/
    docker.py        ephemeral container, version-matched  (default)
    dsn.py           user-supplied scratch DSN, behind interlocks
  stages/
    fetch.py         download, size and checksum
    restore.py       pg_restore / psql, stderr parsing, timing
    structure.py     catalog diff against a reference snapshot
    volume.py        row counts vs tolerance or last known good
    semantics.py     user smoke queries
    integrity.py     sequences, orphaned FKs, collation, amcheck
  report/
    human.py         the default table
    json.py          machine-readable, for trend storage
    junit.py         CI
  history.py         the last-known-good record: counts, durations, versions
```

### Dependencies
`psycopg[binary]`, `PyYAML`, and the standard library. `boto3` only as an extra
(`pip install firedrill[s3]`) so the base install stays small. Docker is driven
through the CLI via `subprocess` with an argument list, not the SDK — one fewer
dependency, and the commands stay inspectable in the log.

### The restore target, concretely
```
docker run --rm -d \
  -e POSTGRES_PASSWORD=<generated> \
  -e POSTGRES_INITDB_ARGS=--data-checksums \
  --tmpfs /var/lib/postgresql/data:rw,size=<n>g \
  postgres:<major>-alpine
```
`--tmpfs` keeps a large restore off the host disk and makes teardown instant.
Fall back to a volume when the backup exceeds available RAM.

### The `Finding` model
Reuse carabiner's shape, which is proven: `stage`, `rule`, `severity`, `message`,
`fix`, `evidence`. No field capable of holding a credential or a row value —
enforced structurally in `__post_init__`, with a test asserting the field set.
This tool touches real customer data during a restore; nothing it prints may
contain any of it.

### Timing
Every stage timed and recorded to `history.json`. RTO is then a measured trend
rather than a claim, and "our restore got 40% slower this quarter" becomes
visible before it matters.

---

## 6. Configuration

```yaml
version: 1

source:
  type: s3
  bucket: acme-backups
  prefix: postgres/daily/
  select: newest          # or a glob, or an explicit key

target:
  type: docker            # docker | dsn
  postgres: auto          # read the major version out of the dump

tier: full                # fast | sample | full
rto_budget: 45m           # exceeded = a finding, not a crash

structure:
  reference: schema/production.sql   # committed, reviewable

volume:
  tolerance: 10%          # vs the last known-good restore
  tables:
    orders:   {min_rows: 1}
    audit_log: {tolerance: 50%}      # append-only, grows fast

semantics:
  - name: recent orders exist
    sql: SELECT count(*) FROM orders WHERE created_at > now() - interval '7 days'
    expect: "> 0"
  - name: no user rows lost their email
    sql: SELECT count(*) FROM app_user WHERE email IS NULL
    expect: "== 0"

ignore:
  - check: COLLATION_MISMATCH
    reason: "restore host is alpine, production is debian; tracked in DR-114"
```

Every `ignore` requires a written reason. An unexplained suppression is a config
error, not a warning — the one piece of process the tool imposes, and the thing
that keeps a green run meaningful. (Carried over from carabiner, where it worked.)

---

## 7. Safety — non-negotiable

This tool restores databases. Getting this wrong is unrecoverable.

- **Refuses any target it did not create**, unless `target.type: dsn` is set
  *and* the DSN's database name matches a scratch pattern *and* the database is
  empty *and* `--i-know-this-is-not-production` is passed. Four interlocks,
  deliberately tedious.
- **Never writes to the source.** Backups are opened read-only; a presigned URL
  or a read-only IAM policy is documented as the recommended setup.
- **Credentials from the environment only.** No `--password`, no `--dsn` flag:
  `/proc/*/cmdline` is world-readable and CI logs echo commands.
- **Teardown in a `finally`**, plus a `firedrill clean` that removes anything
  orphaned by a crash. Containers are labelled so they are findable.
- **No customer data leaves the container.** Smoke queries return *shapes* —
  counts, booleans, comparisons — never rows. The config schema does not permit
  a query whose result is echoed verbatim.
- **A generated, single-use password** for the ephemeral instance, bound to
  localhost, never written to disk.

### The tool's own supply chain
Pinned and hash-locked dependencies, PyPI trusted publishing over OIDC, Sigstore
attestations, SBOM per release, Actions pinned to commit SHAs, and — naturally —
**carabiner in its own CI**.

---

## 8. Testing

Correctness is not "it restored once". It is "it correctly reports each way a
restore can be broken". Build a corpus of deliberately broken backups, generated
by a script so it is reproducible:

```
corpus/
  truncated_dump/          -> RESTORE_FAILED
  missing_extension/       -> EXTENSION_ABSENT
  missing_role/            -> ROLE_ABSENT
  wrong_major_version/     -> VERSION_MISMATCH
  empty_table/             -> VOLUME_DROP
  stale_replica/           -> SEMANTICS_FAILED   (structure passes, data is old)
  sequence_behind_max_id/  -> SEQUENCE_BEHIND
  collation_mismatch/      -> COLLATION_MISMATCH
  healthy/                 -> ZERO findings, and this is the important one
```

Assert the finding set in **both directions**. A false positive fails the build
exactly as hard as a false negative — a DR tool that cries wolf gets muted, and
a muted DR tool is worse than none because it looks like coverage.

`stale_replica` is the fixture that justifies the whole project: every
structural check passes and the data is a week old.

---

## 9. Phases

Each ends with something usable.

**Phase 0 — one restore, honestly reported** *(first)*
Local `pg_dump` custom-format file → ephemeral Docker container → did it work,
and how long did it take. Parse `pg_restore` stderr properly; warnings are
findings.
*Exit:* correct on `healthy/` and `truncated_dump/`.

**Phase 1 — the ladder**
Structure, volume, semantics, integrity. The config file. The `Finding` model.
*Exit:* the whole corpus, both directions, zero findings on `healthy/`.

**Phase 2 — where backups actually live**
S3 and GCS sources, checksum verification, the `fast`/`sample`/`full` tiers.
*Exit:* runs against a real bucket with read-only credentials.

**Phase 3 — CI surface**
GitHub Action, JUnit and JSON output, `history.json` trends, a scheduled
workflow template, a PR comment that says *"restored in 4m12s, 0 findings"*.
*Exit:* a stranger can schedule a nightly restore check in ten lines of YAML.

**Phase 4 — PITR** *(next)*
Base backup plus WAL, restore to a timestamp, assert the boundary row. The check
nobody does.
*Exit:* proven against a fixture with a known write timeline.

Design worked out, mechanics still to be measured:

*The fixture* — one source container with `wal_level=replica`, `archive_mode=on`
and an `archive_command` copying into a mounted directory. Then, in order:
`pg_basebackup -X stream` **first**, so the base precedes the writes; insert row
`before`; record `T = now()`; sleep past the resolution; insert row `after`;
`pg_switch_wal()` and `checkpoint` so the segment carrying both writes is
archived. Ship base + WAL as two directories plus the recorded `T`.

*The restore* — the postgres image only runs `initdb` when `PGDATA` is empty, so
a base backup seeded into it is started rather than initialised. That means an
entrypoint wrapper: copy the base in, `chown` it to postgres (the copy lands as
root, and the entrypoint drops privileges after), `chmod 700` (Postgres refuses a
group-readable data directory), write `recovery.signal`, and append
`restore_command`, `recovery_target_time` and `recovery_target_action = promote`
to `postgresql.conf`.

*The assertion, and the only one that proves anything* — the row written before
`T` **exists** and the row written after it **does not**. Either half alone is
satisfiable by a broken restore: restoring everything passes the first, and
restoring nothing passes the second.

*Known unknowns to measure rather than assume:*
- Whether recovery reaching its target is distinguishable from recovery
  *failing* to reach it. `recovery_target_action = promote` ends with a server
  accepting connections either way, so "the target was reached" needs reading
  back (`pg_last_wal_replay_lsn`, the log line, or the boundary rows
  themselves) — otherwise a PITR that silently stopped early reports as a pass.
- Whether a target timestamp *before* the base backup's own consistency point
  fails loudly or hangs. It must become a finding, not a timeout.
- Clock domains. `T` is recorded by the source server; `recovery_target_time` is
  interpreted by the target's timezone setting. Both should be UTC and it should
  be asserted, not hoped.

**Phase 5 — reach**
MySQL and MongoDB adapters *if and only if* the Postgres one is genuinely solid
and someone asks. Postgres depth beats breadth here.

**Phase 5.5 — the shop window and the field test** *(added mid-project)*

Two things that only make sense once the tool works, and which check each other:

- **A showcase page** (`site/`, deployed by `pages.yml`), in the house visual
  language shared with the portfolio and carabiner: Archivo and a mono, the
  `--void`/`--chalk`/`--alloy` palette, and a metaphor drawn from the project's
  own domain — carabiner stamps a climbing-gear ratings plate, so firedrill
  issues a fire-equipment **inspection tag**. Every number and rule name on it
  must be one the tool actually produces; a test asserts the page quotes no rule
  the code cannot emit, because marketing copy is the text nobody re-reads
  against the source.
- **A field test against real backups** — the corpus is synthetic by
  construction, which is what makes it precise and also what makes it a
  laboratory. Restore dumps that other people made, with the schemas and
  extension habits real projects have: the standard sample databases (pagila,
  dvdrental, chinook, northwind, employees), and any open-source project that
  publishes a seed or demo dump. Record what breaks, honestly, including the
  cases where firedrill is wrong rather than the backup.

*Exit:* the page states only measured facts, and the field test has produced at
least one finding that the synthetic corpus did not — or an explicit statement
that it did not, which is itself a result worth publishing.

**Phase 6 — the writeup**
*"I restored 200 open-source projects' backup scripts and N% produced something
that would not come back."* Gather that number honestly with the tool. That is
the launch.

---

## 10. What it will never do

- **Never take backups.** pgBackRest and WAL-G are excellent; this verifies
  their output. A tool that both takes and verifies its own backups is grading
  its own homework.
- No SaaS, no dashboard, no agent, no account.
- No auto-remediation. It reports; a human decides.
- No AI.
- No writing to production, under any flag, ever.

---

## 11. What this lets you say

- *"How do you know your backups work?"* — We restore one nightly, in CI,
  version-matched, and assert schema, row counts and a business-level smoke
  query. Here is the measured RTO trend.
- *"What is the most dangerous silent failure you know of in Postgres?"* — A
  collation version mismatch on restore. Text indexes sort differently, queries
  return wrong rows, and nothing errors.
- *"Tell me about a control most teams have but have never verified."* — This.
