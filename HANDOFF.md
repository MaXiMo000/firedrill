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

**Phase 0 and Phase 1 are built and green.** `main`, 90 tests / 222
checks / 0 skipped. Repo: <https://github.com/MaXiMo000/firedrill> (public).
CI runs on every push: Linux/Windows × Python 3.10/3.13, plus image, package
and dogfood jobs.

```
firedrill/
  archive.py   custom-format header parsed in pure Python (no host pg client)
  docker.py    ephemeral version-matched container, teardown in a finally
  restore.py   pg_restore inside the container + stderr classifier
  config.py    firedrill.yml -> typed settings, refuses ambiguity   [phase 1]
  ladder.py    structure / volume / semantics / integrity           [phase 1]
  drill.py     inspect -> target -> restore -> smoke -> ladder, each timed
  report.py    human table + --json
  cli.py       run / clean
tests/
  make_corpus.py      builds the broken-backup fixtures from real containers
  test_firedrill.py   90 tests; --require-integration makes a skip a failure
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

**PLAN.md §9 Phase 2 is next** — S3/GCS sources, checksum verification, and
the `fast`/`sample` tiers that `config.py` currently refuses by name. Nothing
from Phase 1 is outstanding.

Two things deliberately deferred, both with the refusal already written so
neither can be mistaken for working:

- `volume.tolerance` is refused by name until Phase 3's `history.json` gives
  it a baseline to compare against. The message says exactly that.
- `target.type: dsn` is refused until §7's four interlocks exist.

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
