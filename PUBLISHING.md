# Publishing firedrill

Everything in this file is account-side setup. The workflows already exist and
are already correct — `release.yml` was written in Phase 0 and has **never
executed**, because nothing has ever been tagged. That is the same "written but
never fired" state the CI workflows were in before the first push, and the first
run of those found a real bug. Expect the same here.

There is no API token anywhere in this repo, and there must never be one. PyPI
publishing uses **Trusted Publishing** over OIDC: PyPI verifies that the upload
came from this repository, this workflow, and this environment, and mints a
short-lived credential for that one upload. A leaked long-lived token is how
supply-chain compromises start.

---

## 0. Before anything: is the name still free?

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/firedrill/json
```

`404` means free. `200` means taken — fall back to `restoreproof`, `backupdrill`
or `recoverydrill`, and change `name = ` in `pyproject.toml` to match.

*Checked 2026-08-25: 404.* Names are first-come, so this is worth re-checking
immediately before step 3 rather than trusting a stale reading.

---

## 1. PyPI: register a pending publisher

You do **not** create the project first. A pending publisher creates it on the
first successful upload.

1. Sign in at <https://pypi.org> (enable 2FA if you have not — PyPI requires it
   for publishing).
2. Go to **Your account → Publishing → Add a new pending publisher**.
3. Fill in exactly:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `firedrill` |
   | Owner | `MaXiMo000` |
   | Repository name | `firedrill` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

The environment name matters. `release.yml` declares `environment: pypi`, and if
the two disagree PyPI rejects the upload with a message about the claim not
matching — which reads like an authentication failure and is not.

**Do the same on TestPyPI first if you want a rehearsal**
(<https://test.pypi.org>, same form). A rehearsal costs one extra tag and
removes the one-shot feeling from the real thing.

---

## 2. GitHub: the environment and the switch

1. **Settings → Environments → New environment**, named `pypi`.
   Optionally add yourself as a required reviewer: every release then waits for
   a human click. For a DR tool that other people's CI will install, that is a
   reasonable amount of friction.
2. **Settings → Secrets and variables → Actions → Variables → New variable**:

   | Name | Value |
   |---|---|
   | `PYPI_ENABLED` | `true` |

   The `pypi` job is gated on this (`if: vars.PYPI_ENABLED == 'true'`) so that
   tagging works before the account side is finished, rather than failing every
   release until it is. Leave it unset until step 1 is done.

---

## 3. Tag it

The tag and the packaged version must agree. `release.yml` enforces this and
fails the release if they do not, because otherwise a tag can ship a tree that
still declares the previous version — and the repo then advertises something
different from what installs.

```bash
# 1. Set the version. This is the single source of truth.
#    (Currently 0.1.0 — bump it if 0.1.0 has already been published.)
grep -n '^version' pyproject.toml

# 2. Tests are the gate, locally as well as in the workflow.
python tests/test_firedrill.py --require-integration

# 3. Commit, tag, push.
git commit -am "Release v0.1.0"
git tag -a v0.1.0 -m "firedrill v0.1.0"
git push origin main --follow-tags
```

Pushing the tag runs `release.yml`:

| Job | What it does | Needs |
|---|---|---|
| `verify` | full suite, then asserts tag == `pyproject.toml` version | — |
| `github-release` | builds sdist+wheel, creates the Release with artefacts attached | `contents: write` |
| `image` | pushes `ghcr.io/maximo000/firedrill` with build provenance attestation | `packages: write` |
| `pypi` | uploads via Trusted Publishing | `id-token: write`, `PYPI_ENABLED` |

---

## 4. Afterwards, verify it as a stranger would

Do not trust the green tick — that is the whole thesis of this project.

```bash
python -m venv /tmp/v && /tmp/v/bin/pip install firedrill
/tmp/v/bin/firedrill --version
/tmp/v/bin/firedrill run some.dump          # it should actually restore
```

And the S3 extra, which is a separate install path that CI covers but PyPI has
never served:

```bash
/tmp/v/bin/pip install 'firedrill[s3]' && /tmp/v/bin/python -c "import boto3"
```

---

## 5. The container image

`release.yml` already pushes to GHCR with a provenance attestation, so anyone
can verify the image came from this repo and this workflow rather than from
someone who pushed a tag with the same name:

```bash
gh attestation verify oci://ghcr.io/maximo000/firedrill:0.1.0 --owner MaXiMo000
```

New GHCR packages are **private by default**. After the first release:
**GitHub → your profile → Packages → firedrill → Package settings → Change
visibility → Public**. Otherwise `docker pull` fails for everyone else with a
message about authentication, which looks like a bug in your Dockerfile.

---

## 6. GitHub Pages (the showcase site)

**Live: <https://maximo000.github.io/firedrill/>**

Pages must be enabled **once**, out of band, and this is not optional
hand-waving: the workflow cannot do it for you. `actions/configure-pages` takes
an `enablement: true` flag, and it fails with *"Resource not accessible by
integration"* — creating a Pages site needs admin rights that `GITHUB_TOKEN`
does not have, whatever `permissions:` you grant it.

Either click **Settings → Pages → Build and deployment → Source: GitHub
Actions**, or do it from the CLI:

```bash
gh api -X POST repos/MaXiMo000/firedrill/pages -f build_type=workflow
```

After that, `pages.yml` deploys `site/` on every push that touches it, and no
tag is needed. `enablement: true` stays in the workflow so a fork gets the
clearer error rather than a bare 404.

Optionally set it as the repo's homepage: **About → ⚙ → Website**.

---

## 7. The GitHub Action

`action.yml` is usable the moment a tag exists — `MaXiMo000/firedrill@v0.1.0`
works with no further setup. Two things worth doing:

- **A moving major tag**, so users can pin `@v0` and get fixes:

  ```bash
  git tag -f v0 v0.1.0 && git push -f origin v0
  ```

  Note that this is one of the few legitimate force-pushes; it is also why
  `examples/` tells people to pin a SHA if they want immutability.

- **Marketplace listing** (optional): on the Release page, tick *"Publish this
  Action to the GitHub Marketplace"*. It needs `action.yml` to have `name`,
  `description` and `branding`, which it does.

**Until a tag exists, the action's default install path cannot work** — it runs
`pip install firedrill[s3]`, and there is nothing on PyPI to install. CI covers
it today with `install-from: .`, so publishing is what makes the action real for
anyone else.

---

## The order that avoids dead ends

1. Check the name is free (§0).
2. Register the pending publisher on PyPI (§1) — before tagging, or the `pypi`
   job has nothing to authenticate against.
3. Create the `pypi` environment and set `PYPI_ENABLED` (§2).
4. Tag (§3).
5. Make the GHCR package public (§5) and turn on Pages (§6).
6. Move the `v0` tag (§7).
7. Install it from PyPI in a clean venv and actually run a restore (§4).

Step 7 is not ceremony. Every other step reports success on its own terms; only
that one proves a stranger can use what you published.
