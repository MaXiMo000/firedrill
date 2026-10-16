# Changelog

## Unreleased

- `firedrill demo`: drills a sample backup and a cut-off copy of it, and shows that psql restores the cut copy with exit 0. Needs only Docker.
- `firedrill doctor` prints how to fix each failed check: install or start Docker, switch to Linux containers, socket permissions, scratch space, config.
- Fixed: on Windows (or any non-UTF-8 locale), a single non-ASCII byte in a restore's output made firedrill lose that output entirely. Command output is now always decoded as UTF-8.

## 0.5.1 - 2026-10-16

- Documentation: a demo of real output at the top of the README, a security policy, a changelog, and issue templates.

## 0.5.0 - 2026-10-02

- Restore pgBackRest and WAL-G backups with the tool itself (`firedrill physical`).
- Webhook alerts on failure with `--notify`.

## 0.4.0 - 2026-09-27

- Drill a live database with `--live`, keeping the verified dump with `--keep`.
- `s3://` URLs, including the newest object under a prefix.
- Restore into extension images such as pgvector with `--image`.
- Plain-SQL restores now catch errors psql prints without a file prefix.

## 0.3.0 - 2026-09-26

- Plain SQL dumps (`.sql`, `.sql.gz`), with truncated dumps reported as `ARCHIVE_TRUNCATED`.

## 0.2.1 - 2026-09-26

- `firedrill doctor` checks the environment before a run.
- Unpopulated materialized views are reported.
- An unverified fetch is reported as unverified, not ok.
- A hung Docker command fails the run instead of crashing it.

## 0.2.0 - 2026-08-26

- Directory and tar dumps.
- PostgreSQL 13 to 18 tested end to end.
- Structure checks cover views, routines, triggers, RLS policies, types and `NOT VALID` constraints.

## 0.1.1 - 2026-08-25

- GitHub Marketplace action name.

## 0.1.0 - 2026-08-25

- First release: restore a custom-format dump into a version-matched container and report each stage.
