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

Nothing built. This folder is the plan.

## First move in the new chat

`PLAN.md` §9 Phase 0: restore a `pg_dump` custom-format file into a throwaway
container and report whether it worked, with timings. One source format, one
target, no cloud. Get that genuinely solid before adding anything.
