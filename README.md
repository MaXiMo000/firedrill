# firedrill

**You don't have backups. You have hopes.**

firedrill takes a Postgres backup and *actually restores it* into a disposable,
version-matched container, then reports whether it worked and how long each
stage took. It is built to fail your build the day a backup stops being
restorable — not the day you need it.

> A verification that could not run never reports as passing.

That rule is the whole design. No Docker, an unreadable archive, a container
that never came up — every one of those produces **COULD NOT VERIFY** and a
non-zero exit, never a green tick. A backup tool that says "OK" because it
silently skipped the restore is worse than no tool, because it manufactures
confidence.

## Status

**Phase 0.** One local `pg_dump` custom-format file, restored into an ephemeral
container, honestly reported. The checks that compare schema, row counts and
business-level smoke queries are Phase 1 — see `PLAN.md`.

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
firedrill clean                            # remove containers left by a crash
```

Exit code is `0` only when the restore genuinely ran and produced no finding at
or above `--fail-on` (default `high`).

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

## Licence

MIT.
