"""firedrill command line.

No --dsn and no --password, by design (PLAN.md §7): /proc/*/cmdline is
world-readable and CI logs echo command lines. Phase 0 needs neither, because
the only target it can build is one it created itself.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, docker, drill, report as reporting
from .finding import SEVERITIES


def _duration(text: str) -> float:
    """'45m', '90s', '2h', or bare seconds."""
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    if text and text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firedrill",
        description="Restore a Postgres backup into a disposable container and "
                    "report whether it actually worked.",
    )
    parser.add_argument("--version", action="version",
                        version=f"firedrill {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="restore a dump and report")
    run.add_argument("dump", help="path to a pg_dump custom-format (-Fc) file")
    run.add_argument("--json", metavar="PATH",
                     help="write the machine-readable report here ('-' for stdout)")
    run.add_argument("--rto", metavar="DURATION",
                     help="recovery-time budget, e.g. 45m. Exceeding it is a "
                          "finding, not a crash.")
    run.add_argument("--fail-on", choices=SEVERITIES, default="high",
                     help="lowest severity that fails the run (default: high)")
    run.add_argument("--postgres", metavar="MAJOR",
                     help="override the major version read from the archive")
    run.add_argument("--image-flavour", default="",
                     help="suffix for the postgres image, e.g. '-alpine'. Not the "
                          "default: musl libc breaks collation comparisons.")
    run.add_argument("--ready-timeout", type=int,
                     default=docker.DEFAULT_READY_TIMEOUT,
                     help="seconds to wait for the container (default: %(default)s)")
    run.add_argument("--quiet", action="store_true", help="suppress the table")

    sub.add_parser("clean", help="remove containers left behind by a crash")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "clean":
        usable, why = docker.docker_available()
        if not usable:
            print(f"docker is not usable: {why}", file=sys.stderr)
            return 1
        removed = docker.clean()
        print(f"removed {len(removed)} container(s)"
              + (": " + ", ".join(removed) if removed else ""))
        return 0

    result = drill.run(
        args.dump,
        flavour=args.image_flavour,
        rto_budget=_duration(args.rto) if args.rto else None,
        fail_on=args.fail_on,
        pin_major=args.postgres,
        ready_timeout=args.ready_timeout,
    )

    if not args.quiet:
        print(reporting.human(result))
    if args.json:
        blob = reporting.as_json(result)
        if args.json == "-":
            print(blob)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(blob + "\n")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
