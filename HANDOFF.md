# firedrill — start here

Cold-start handoff. Read this, then `PLAN.md`. Nothing depends on remembering an
earlier conversation.

## The project in one line

**You don't have backups. You have hopes.**

firedrill takes a database backup and *actually restores it*, then proves the
result is usable: schema matches, data is there, a smoke query returns something
sane, and it all happened inside your recovery-time budget. It fails your build
the day a backup stops being restorable — not the day you need it.

## Who this is for

**Ritish Saini** — backend engineer at WizCommerce. Deep Postgres: query-plan
tuning, generic-plan vs partial-index traps, statement timeouts, row-level
security. Python and JavaScript. GitHub `MaXiMo000`.

`firedrill` is available on PyPI (checked 2026-08-23). Alternates if it is taken
by then: `restoreproof`, `backupdrill`, `recoverydrill`.

## Why this and not something else

It continues a thesis rather than starting a new one. Ritish's last two projects
share a single idea:

> **Verify the control. Do not trust the configuration.**

- **carabiner** — plants a private key and checks the pre-commit hook actually
  blocks it; asks GitHub whether push protection is genuinely on. A check that
  *could not run* never reports as passing.
- **recur** — Postgres row-level security with adversarial tests that
  deliberately try to read across tenants.

A backup that has never been restored is the purest example of the same problem:
a control everybody has configured and almost nobody has verified.

## The rule that carries over from carabiner

Written here because it is the single most important design constraint, it was
learned the hard way, and a new chat will not infer it:

> **A verification that could not run never reports as passing.**

No credentials, no disk space, a truncated dump, a missing extension — every one
of those produces "could NOT be verified", never a green tick. A backup tool
that says "OK" because it silently skipped the restore is worse than no tool,
because it manufactures confidence.

## Second rule, specific to this project

> **Never touch production. Ever.**

This tool restores databases. A restore pointed at the wrong DSN is a
catastrophe measured in careers. See `PLAN.md` §7 — the safety interlocks are
not a feature, they are the price of admission.

## Status

**Phases 0–4 are built and green.** `main`, 122 tests / 371
checks / 0 skipped. Repo: <https://github.com/MaXiMo000/firedrill> (public).
CI runs on every push: Linux/Windows × Python 3.10/3.13, plus image, package
and dogfood jobs.

```
firedrill/
  archive.py   custom-format header parsed in pure Python (no host pg client)
  docker.py    ephemeral version-matched container, teardown in a finally
  restore.py   pg_restore inside the container + stderr classifier
  config.py    firedrill.yml -> typed settings, refuses ambiguity   [phase 1]
  sources.py   local / https / s3, read-only by construction        [phase 2]
  history.py   last-known-good: durations, row counts, versions      [phase 3]
  pitr.py      recover a base backup to a timestamp, then assert       [phase 4]
  ladder.py    structure / volume / semantics / integrity           [phase 1]
  drill.py     inspect -> target -> restore -> smoke -> ladder, each timed
  report.py    human table + --json
  cli.py       run / clean
tests/
  make_corpus.py      builds the broken-backup fixtures from real containers
  test_firedrill.py   122 tests; --require-integration makes a skip a failure
  field_test.py       restores pagila/chinook/northwind -- databases we did not write
  headers/            512-byte committed headers so the parser is testable
                      on a runner that cannot run Linux containers
```

### Pushing, if you are on the other GitHub account

The repo belongs to `MaXiMo000`; this machine's SSH key belongs to
`Ritishsaini06`, so `origin` is HTTPS with a repo-local `gh` credential
helper. `gh` serves whichever account is *active*, so before pushing:

```bash
gh auth switch --user MaXiMo000
```

`firedrill run <dump.dump>` → per-stage timings and a verdict that separates
**FAIL** from **COULD NOT VERIFY**. Exit 0 only when the restore genuinely ran
and found nothing at or above `--fail-on` (default `high`).

### Decisions already argued and settled

- **Debian `postgres:<major>`, never alpine by default.** musl vs glibc would
  mismatch collation by default — the exact silent corruption §3.4 exists to
  detect. A test pins the default so it cannot drift back.
- **`pg_restore` runs inside the container**, so client and server are both the
  dump's major version and the host needs no Postgres client at all.
- **The header is parsed in pure Python**, decoded from real dumps (archive
  1.14 / 1.15 / 1.16). This resolves a bootstrap problem: you cannot ask a
  version-matched container what version to be.
- **No `--tmpfs`.** Its fallback rule needs the restored size, which a
  compressed archive cannot tell you.
- **No DSN target exists yet** — the safest implementation of "refuses any
  target it did not create" is to have no other target. §7's four interlocks
  arrive with the DSN target.
- **No dependencies.** Phase 0 is stdlib only. Phase 1 added **PyYAML** and
  nothing else.

### Decisions added during Phase 1

- **No psycopg, and no published port.** This overturns PLAN.md §5. Phase 0
  already shipped `container.sql()`, and `docker.py` publishes no port at all
  — "not reachable from the host" is a §7 safety property. psycopg would have
  required spending it to get typed results for queries that only ever return
  a single number. Every rung uses `docker exec psql -tA`.
- **`ladder.py` is one flat module**, not the `stages/` package §5 sketches.
  Four functions sit beside `archive.py` and `restore.py`, matching the layout
  the package already has.
- **`NOT_CONFIGURED` is a distinct stage status.** "Nothing asked for this" and
  "this was asked for and could not run" are different facts, and neither is a
  tick. The report prints `n/a`.
- **Suppression is applied in one place**, wrapping `_run`, because `_run` can
  return from five points and a missed one would silently un-suppress a
  finding — or hide one nobody asked to hide. Suppressed findings are printed
  with their written reason, never deleted.
- **The structure reference excludes internal schemas and `contype = 'n'`.**
  Both were measured, not reasoned: `pg_toast` indexes made the first
  reference 48 lines of per-database OIDs, and PG18 materialises NOT NULL as
  `pg_constraint` rows where PG16 does not, so a pg16 reference called every
  not-null column drift on pg18. One reference is now portable across majors,
  and a test asserts it.

### Correction to PLAN.md §3.3

§3.3 says a missing role or extension surfaces as a *warning with a zero exit
code*. **Measured on PG 16 and 18, custom format: the exit code was 1 in every
broken case**, alongside `warning: errors ignored on restore: N`. The exit code
is still insufficient — it is one bit, so it never says *which* failure — so
stderr classifies and the exit code is a backstop. `EXIT_CODE_LIED` is kept as
a guard, not as a dependency on that measurement holding.

## First move in the new chat

**Phase 1 is complete.** Every PLAN.md §8 fixture is built and every check is
asserted in both directions against a real broken backup. What is left:

**Phases 0–4 are done, plus the showcase and a field test. PLAN.md §9 Phase 5
is next** (MySQL/Mongo adapters — *only* if someone asks; Postgres depth beats
breadth), and **Phase 6, the writeup**.

Phase 4 is PITR: `firedrill pitr --base DIR --wal DIR --target 'TS'`. The
boundary assertion is expressed as ordinary `semantics:` checks — the row
written before the target must exist, the one after must not — because either
half alone is satisfiable by a restore that is simply wrong.

`tests/field_test.py` restores pagila, chinook and northwind: real databases
this project did not write. Run it after touching any check.

**Still unproven:** `firedrill` is not on PyPI, so the action's default install
path has never executed and `release.yml` has never run. `PUBLISHING.md` has
the steps in the order that avoids dead ends.

Deferred, each with its refusal already written:

- `target.type: dsn` — until §7's four interlocks exist.
- `source.type: gcs` — refused, pointing at `type: https` with a signed URL.

### Measurements worth not rediscovering

- `pg_restore --data-only -t customer` restores every row and leaves the
  sequence at **1**: setval is not part of a table-scoped data restore. That
  is why the sample tier does not check sequences — it would report
  SEQUENCE_BEHIND on a healthy backup.
- `[project.optional-dependencies]` must sit **after** the bare `urls.*` keys
  in `pyproject.toml`. Opening it above them reparents them and breaks the
  build, while the whole suite still passes — the suite imports the source
  tree and never builds it. A test pins the ordering.
- On the Windows runners, `bash` is the WSL stub: `bash -n` exits **1 with
  empty stderr** for a valid script. Probe a tool before trusting its exit
  code — the same lesson as `docker info` exiting 0 with no server version.
- YAML reads a bare all-digit `sha256:` as a *number* and drops leading
  zeros, so the value that arrives is not the value written. Quote it.
- **`pg_get_serial_sequence` resolves nothing for a sequence wired only by a
  column DEFAULT.** pagila does exactly that for all 13 of its sequences. Any
  check that finds sequences through `pg_depend` ownership alone will examine
  none of them and report zero, which reads as fine.
- **`recovery_target_time` is "reached" only if a commit with a LATER
  timestamp exists in the WAL.** A target after the final commit is reported
  *unreached*, not satisfied at end-of-WAL.
- **`pg_walfile_name(pg_switch_wal())` names the segment that is now current**,
  not the one just completed. Take the name before switching.
- **A failing `restore_command` is mute.** Postgres treats it as "segment
  unavailable", so an unreadable WAL archive produces no error line — only an
  absence of `restored log file` lines and a target that cannot be reached.
- **Bind-mount uid mismatches break only on Linux.** Docker Desktop makes bind
  mounts world-writable; a clean Linux host does not. This broke four separate
  things here, each invisible locally. Copy into the container and `chown`
  rather than relying on the host's permissions.

### Two things that turned out easier than this file previously claimed

Both were recorded here as needing purpose-built images. Measuring first
changed the answer:

- **Collation** needed no new image. `--image-flavour -alpine` already
  provides a musl target against the default glibc one. Measured:
  `postgres:16` reports `datcollversion = 2.41`, `postgres:16-alpine` reports
  **empty** — musl reports no version at all, which is why there are two
  rules (`COLLATION_UNVERIFIABLE` and `COLLATION_MISMATCH`) rather than one.
- **Extensions** did need one, but not for the assumed reason. The alpine
  image *lists* `plperl` / `plpython3u` / `pltcl` in `pg_available_extensions`
  and ships none of their runtime libraries, so they cannot be created on
  either variant — available is not loadable. `make_corpus.build_noext_image`
  builds `postgres:16-firedrill-noext` with hstore's control file removed,
  which is what a real recovery host without the binaries looks like.

Run the suite before changing anything:

```bash
cd firedrill && python tests/test_firedrill.py --require-integration
```

It needs Docker. `--require-integration` turns a skipped container test into a
build failure, which is the point: a run that did not happen must never look
like one that passed.
