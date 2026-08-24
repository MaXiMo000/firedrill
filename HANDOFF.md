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

**Phase 0 is built and green.** Branch `phase-0`, two commits, 47 tests / 99
checks / 0 skipped. There is **no git remote** — nothing is pushed anywhere yet.

```
firedrill/
  archive.py   custom-format header parsed in pure Python (no host pg client)
  docker.py    ephemeral version-matched container, teardown in a finally
  restore.py   pg_restore inside the container + stderr classifier
  drill.py     inspect -> target -> restore -> smoke, each timed
  report.py    human table + --json
  cli.py       run / clean
tests/
  make_corpus.py      builds the broken-backup fixtures from real containers
  test_firedrill.py   47 tests; --require-integration makes a skip a failure
  headers/            512-byte committed headers so the parser is testable
                      on a runner that cannot run Linux containers
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
- **No dependencies.** Phase 0 is stdlib only; psycopg arrives in Phase 1.

### Correction to PLAN.md §3.3

§3.3 says a missing role or extension surfaces as a *warning with a zero exit
code*. **Measured on PG 16 and 18, custom format: the exit code was 1 in every
broken case**, alongside `warning: errors ignored on restore: N`. The exit code
is still insufficient — it is one bit, so it never says *which* failure — so
stderr classifies and the exit code is a backstop. `EXIT_CODE_LIED` is kept as
a guard, not as a dependency on that measurement holding.

## First move in the new chat

Two things are outstanding before Phase 1:

1. **`phase-0` is unmerged and there is no remote.** Decide whether to
   fast-forward `main`, and whether to create the GitHub repo. The CI and
   release workflows are written but **have never executed** — the
   Linux/Windows matrix is unproven until something is pushed.
2. **Then `PLAN.md` §9 Phase 1** — the ladder: structure, volume, semantics,
   integrity, the config file, the `Finding` model's remaining severities.
   `tests/make_corpus.py` already lists the §8 fixtures still to build and the
   technique each one needs, at the bottom of the file.

Run the suite before changing anything:

```bash
cd firedrill && python tests/test_firedrill.py --require-integration
```

It needs Docker. `--require-integration` turns a skipped container test into a
build failure, which is the point: a run that did not happen must never look
like one that passed.
