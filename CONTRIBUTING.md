# Contributing

Bug reports and pull requests are welcome.

## Setup

```bash
git clone https://github.com/MaXiMo000/firedrill
cd firedrill
python -m pip install -e ".[s3]" ruff==0.16.8
```

## Before opening a pull request

```bash
ruff check .
python tests/test_firedrill.py
```

The restore tests need Docker. Without it they skip and the run says how many;
add `--require-integration` to make a skip fail the run, as CI does on Linux.

- Keep changes focused: one fix or feature per pull request.
- Add a test that fails without your change.
- A check that could not run must never report as passing. New checks follow the
  same pass / fail / unverified rule as the existing ones.
- Update `README.md` and `CHANGELOG.md` when behaviour changes.

## Reporting a security problem

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
