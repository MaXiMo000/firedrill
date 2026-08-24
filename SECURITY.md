# Security

## Reporting

Open a private security advisory on the repository. Please do not file a public
issue for anything exploitable.

## What this tool is trusted with

firedrill restores database backups, which means it handles real customer data
during a run. The design constraints that follow from that live in `PLAN.md`
§7; the ones enforced in code today are:

- **It only ever uses a target it created itself.** There is no code path that
  connects to a user-supplied DSN, so there is no code path that can be aimed
  at production by accident. The DSN target and its interlocks arrive with a
  later phase.
- **The source is mounted read-only.** "Never writes to the backup" is a
  property of the bind mount, not a promise about our own code.
- **No credentials on the command line.** There is no `--dsn` and no
  `--password` flag. The ephemeral container's password is generated per run,
  passed to Docker by environment-variable *name* so it never enters argv
  (`/proc/*/cmdline` is world-readable), and never written to disk.
- **No port is published.** The target container is unreachable from the host;
  everything goes through `docker exec`.
- **Findings cannot carry data.** The `Finding` model has a fixed field set
  with nothing capable of holding a row or a result set, asserted by a test.
  Everything printed passes through a redactor that strips connection-string
  credentials and any password the run generated.

## Supply chain

- GitHub Actions are pinned to full commit SHAs.
- Releases publish to PyPI via trusted publishing (OIDC); no long-lived token
  is stored in this repository.
- Container images carry build provenance attestations.
- carabiner runs against this repository in CI.
