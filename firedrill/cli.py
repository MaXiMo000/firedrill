"""firedrill command line.

No --dsn and no --password, by design (PLAN.md §7): /proc/*/cmdline is
world-readable and CI logs echo command lines. Phase 0 needs neither, because
the only target it can build is one it created itself.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import sys

from . import __version__, config, docker, drill, report as reporting
from .config import parse_duration as _duration
from .finding import SEVERITIES


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
    run.add_argument("--config", metavar="PATH",
                     help="firedrill.yml to read (default: one beside you, if "
                          "there is one)")
    run.add_argument("--no-config", action="store_true",
                     help="ignore any firedrill.yml that is lying around")
    run.add_argument("--write-reference", metavar="PATH",
                     help="write the restored catalog here as a structure "
                          "reference, instead of comparing against one. Commit "
                          "the result and review it like any other file.")
    run.add_argument("--tier", choices=config.ALL_TIERS,
                     help="how much to restore. `fast` is schema-only: the "
                          "row-reading checks then report NOT RUN, never a pass.")
    run.add_argument("--junit", metavar="PATH",
                     help="write a JUnit XML report here, for CI to display")
    run.add_argument("--history", metavar="PATH",
                     help="append this run to a history file, and measure it "
                          "against the last known-good run recorded there")
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

    # An explicitly named config that cannot be read is a hard error. Falling
    # back to defaults would run a weaker set of checks than the user asked
    # for and still print a pass.
    try:
        if args.no_config:
            cfg = config.DEFAULT
        elif args.config:
            cfg = config.load(args.config)
        else:
            found = config.find()
            cfg = config.load(found) if found else config.DEFAULT
            if found and not args.quiet:
                print(f"using {found}")
        if args.history:
            cfg = dataclasses.replace(cfg, history_path=pathlib.Path(args.history))
        if args.tier:
            cfg = dataclasses.replace(cfg, tier=args.tier)
            if args.tier not in config.IMPLEMENTED_TIERS:
                raise config.ConfigError(
                    f"tier {args.tier!r} is not implemented yet; "
                    f"available: {', '.join(config.IMPLEMENTED_TIERS)}")
    except config.ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    result = drill.run(
        args.dump,
        cfg=cfg,
        write_reference=args.write_reference,
        flavour=args.image_flavour,
        rto_budget=_duration(args.rto) if args.rto else None,
        fail_on=args.fail_on,
        pin_major=args.postgres,
        ready_timeout=args.ready_timeout,
    )

    if not args.quiet:
        print(reporting.human(result))
    if args.junit:
        with open(args.junit, "w", encoding="utf-8") as handle:
            handle.write(reporting.as_junit(result))
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
