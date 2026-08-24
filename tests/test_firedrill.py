"""Run: python tests/test_firedrill.py [--require-integration]

Two rules this suite exists to enforce, both learned the expensive way:

* Findings are asserted in BOTH directions. A false positive fails this build
  exactly as hard as a false negative. A DR tool that cries wolf gets muted,
  and a muted DR tool is worse than none because it still looks like coverage.

* A test that could not run is counted and named, never quietly absent. Pass
  --require-integration on a platform where the container tests must run
  (Linux CI) and the suite fails if any of them skipped. Otherwise "0 tests
  ran" and "all tests passed" are the same green, which is the failure this
  whole project is about.
"""

from __future__ import annotations

import dataclasses
import io
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from firedrill import archive, docker, drill, report as reporting, restore
from firedrill.cli import _duration, build_parser
from firedrill.finding import (
    Finding, SEVERITIES, forget_secrets, redact, register_secret, should_fail, worst,
)

HERE = pathlib.Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
HEADERS = HERE / "headers"

FAILURES: list[str] = []
SKIPPED: list[str] = []
CHECKS = [0]


class Skip(Exception):
    """Raised by a test that genuinely cannot run here."""


def check(label, got, expected):
    CHECKS[0] += 1
    if got != expected:
        FAILURES.append(f"  {label}\n    expected {expected!r}\n    got      {got!r}")


def check_true(label, got):
    check(label, bool(got), True)


def needs_docker():
    usable, why = docker.docker_available()
    if not usable:
        raise Skip(f"docker unavailable: {why}")


def corpus(name: str) -> pathlib.Path:
    """A fixture path, building the corpus on first use."""
    path = CORPUS / name
    if path.exists():
        return path
    needs_docker()
    import make_corpus
    make_corpus.build(CORPUS)
    if not path.exists():
        raise Skip(f"fixture {name} was not produced")
    return path


# ---------------------------------------------------------------- archive --
# The header layout was decoded from real dumps. These headers are committed
# so the parser stays covered on platforms that cannot run Linux containers.

def test_header_pg16():
    header = archive.read_header(HEADERS / "pg16.header")
    check("pg16 archive version", header.archive_version, (1, 15, 0))
    check("pg16 format", header.format_name, "custom")
    check("pg16 major", header.server_major, "16")


def test_header_pg18():
    header = archive.read_header(HEADERS / "pg18.header")
    check("pg18 archive version", header.archive_version, (1, 16, 0))
    check("pg18 major", header.server_major, "18")


def test_header_compression_field_width_changed_at_1_15():
    """PG 15 and earlier write compression as an Int; 1.15+ writes one byte.

    Getting this wrong shifts every subsequent field and yields a plausible
    but wrong version string, so it is pinned rather than trusted.
    """
    header = archive.read_header(HEADERS / "pg16.header")
    check("1.15 reads gzip as a single byte", header.compression, 1)
    check("and the dbname still lands", header.dbname, "postgres")


def test_major_of():
    check("modern", archive.major_of("16.15 (Debian 16.15-1.pgdg13+2)"), "16")
    check("plain", archive.major_of("18.6"), "18")
    check("pre-10 keeps two components", archive.major_of("9.6.24"), "9.6")
    for bad in ("", None, "not a version"):
        try:
            archive.major_of(bad)
            FAILURES.append(f"  major_of({bad!r}) should have raised")
        except archive.ArchiveError:
            CHECKS[0] += 1


def test_truncated_header_is_an_error_not_a_guess():
    try:
        archive.parse_header(b"PGDMP\x01\x0f\x00\x04\x08\x01")
        FAILURES.append("  truncated header should raise ArchiveError")
    except archive.ArchiveError as exc:
        check("says where it ran out", "mid-header" in str(exc), True)


def test_plain_sql_is_rejected_with_a_useful_message():
    try:
        archive.parse_header(b"--\n-- PostgreSQL database dump\n--\nSET x=1;\n")
        FAILURES.append("  plain SQL should raise ArchiveError")
    except archive.ArchiveError as exc:
        check("names the magic", "PGDMP" in str(exc), True)
        check("suggests the cause", "plain-SQL" in str(exc), True)


def test_absurd_string_length_is_rejected():
    """A corrupt length field is how a damaged header usually presents."""
    blob = b"PGDMP" + bytes([1, 15, 0, 4, 8, 1, 1]) + b"\x00\xff\xff\xff\x7f" * 12
    try:
        archive.parse_header(blob)
        FAILURES.append("  absurd length should raise")
    except archive.ArchiveError:
        CHECKS[0] += 1


def test_empty_and_missing_files():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp) / "e.dump"
        empty.write_bytes(b"")
        for path, word in ((empty, "empty"), (pathlib.Path(tmp) / "nope", "no such")):
            try:
                archive.read_header(path)
                FAILURES.append(f"  {path} should raise")
            except archive.ArchiveError as exc:
                check(f"{word} is explained", word in str(exc), True)


# ------------------------------------------------------- stderr classifier --
# Transcripts below are copied verbatim from measured pg_restore output on
# PostgreSQL 16 and 18. If a future release rewords these, these tests fail --
# which is the point.

ROLE_TRANSCRIPT = (
    'pg_restore: error: could not execute query: ERROR:  role "appuser" does not exist\n'
    "Command was: ALTER TABLE public.owned OWNER TO appuser;\n"
    "\n"
    "pg_restore: warning: errors ignored on restore: 1\n"
)
TRUNCATED_TRANSCRIPT = "pg_restore: error: could not read from input file: end of file\n"


def test_healthy_restore_produces_nothing():
    """The single most important assertion in the file."""
    findings, ignored = restore.parse_stderr("", 0)
    check("clean stderr, clean exit -> no findings", findings, [])
    check("and no ignored errors", ignored, 0)


def test_role_absent_is_classified():
    findings, ignored = restore.parse_stderr(ROLE_TRANSCRIPT, 1)
    check("rule", [f.rule for f in findings], ["ROLE_ABSENT"])
    check("severity", findings[0].severity, "high")
    check("ignored count is read from the summary", ignored, 1)


def test_truncation_is_classified():
    findings, _ = restore.parse_stderr(TRUNCATED_TRANSCRIPT, 1)
    check("rule", [f.rule for f in findings], ["ARCHIVE_TRUNCATED"])
    check("severity", findings[0].severity, "critical")


def test_unrecognised_error_still_fails():
    """An error we cannot classify must not become silence."""
    findings, _ = restore.parse_stderr(
        "pg_restore: error: something nobody has seen before\n", 1)
    check("falls back to RESTORE_ERROR", [f.rule for f in findings], ["RESTORE_ERROR"])


def test_nonzero_exit_with_no_stderr_is_never_a_pass():
    findings, _ = restore.parse_stderr("", 3)
    check("backstop fires", [f.rule for f in findings], ["RESTORE_FAILED"])
    check("severity", findings[0].severity, "critical")


def test_exit_zero_with_errors_is_caught():
    """PLAN.md §3.3's scenario. Measured exit codes were 1, but the guard stays:
    the tool must not depend on that remaining true."""
    findings, _ = restore.parse_stderr(ROLE_TRANSCRIPT, 0)
    check("both the cause and the lie are reported",
          sorted(f.rule for f in findings), ["EXIT_CODE_LIED", "ROLE_ABSENT"])


def test_warnings_are_findings_not_noise():
    findings, _ = restore.parse_stderr("pg_restore: warning: something odd\n", 0)
    rules = sorted(f.rule for f in findings)
    check("warning is reported", "RESTORE_WARNING" in rules, True)


def test_repeated_identical_errors_collapse():
    """A 40-table restore failing the same way is one finding, not 40 lines."""
    line = 'pg_restore: error: could not execute query: ERROR:  role "a" does not exist\n'
    findings, _ = restore.parse_stderr(line * 40, 1)
    check("deduplicated", len(findings), 1)


def test_different_errors_do_not_collapse():
    stderr = (
        'pg_restore: error: could not execute query: ERROR:  role "a" does not exist\n'
        'pg_restore: error: could not execute query: ERROR:  role "b" does not exist\n'
    )
    findings, _ = restore.parse_stderr(stderr, 1)
    check("two distinct roles, two findings", len(findings), 2)


def test_non_pg_restore_lines_are_ignored():
    """Container noise on the same stream must not manufacture findings."""
    findings, _ = restore.parse_stderr(
        "some unrelated line\nWARNING: this is not from pg_restore\n", 0)
    check("no findings from noise", findings, [])


# ---------------------------------------------------------------- finding --

def test_finding_field_set_is_locked():
    """Structural guarantee: no field exists that could hold a row or a secret.

    If someone adds `rows` or `password` to Finding, this fails before the
    reporters ever get a chance to print it.
    """
    names = [f.name for f in dataclasses.fields(Finding)]
    check("exact field set", names,
          ["stage", "rule", "severity", "message", "fix", "evidence"])


def test_finding_rejects_unknown_severity():
    try:
        Finding("s", "R", "catastrophic", "m")
        FAILURES.append("  unknown severity should raise")
    except ValueError:
        CHECKS[0] += 1


def test_redaction_removes_session_secrets():
    forget_secrets()
    register_secret("s3cret-token-value")
    f = Finding("s", "R", "high", "connecting with s3cret-token-value now")
    check("session secret gone", "s3cret-token-value" in f.message, False)
    check("marker present", "[redacted]" in f.message, True)
    forget_secrets()


def test_redaction_removes_uri_and_keyword_credentials():
    check("uri", redact("postgres://user:pw@host/db"), "postgres://[redacted]@host/db")
    check("keyword", redact("password=hunter2"), "password=[redacted]")
    check("pgpassword", redact("PGPASSWORD: abc123"), "PGPASSWORD: [redacted]")


def test_short_secrets_are_not_registered():
    """Registering 'x' would redact every x in every report."""
    forget_secrets()
    register_secret("ab")
    check("too short to register", redact("ab cd"), "ab cd")
    forget_secrets()


def test_evidence_is_capped():
    f = Finding("s", "R", "low", "m", evidence="x" * 9000)
    check("capped", len(f.evidence) <= 2100, True)
    check("says it was cut", f.evidence.endswith("[truncated]"), True)


def test_severity_helpers():
    findings = [Finding("s", "A", "medium", "m"), Finding("s", "B", "critical", "m")]
    check("worst", worst(findings), "critical")
    check("empty", worst([]), None)
    check("fails on high", should_fail(findings, "high"), True)
    check("medium-only does not trip critical",
          should_fail([Finding("s", "A", "medium", "m")], "critical"), False)


# ------------------------------------------------------------------ report --

def _blank_report(verified: bool, findings=()):
    return drill.Report(
        dump="d.dump", stages=[drill.Stage(n) for n in drill.STAGES],
        findings=list(findings), archive={}, verified=verified,
    )


def test_unverified_is_never_ok_even_with_no_findings():
    """The rule the whole tool is built on. A run that did not happen is not a pass."""
    report = _blank_report(verified=False)
    check("not ok", report.ok, False)
    check("non-zero exit", report.exit_code, 1)


def test_verified_and_clean_is_ok():
    report = _blank_report(verified=True)
    check("ok", report.ok, True)
    check("exit 0", report.exit_code, 0)


def test_verified_with_findings_is_not_ok():
    report = _blank_report(verified=True, findings=[Finding("s", "R", "high", "m")])
    check("not ok", report.ok, False)


def test_human_report_distinguishes_could_not_verify_from_fail():
    unverified = reporting.human(_blank_report(verified=False))
    failed = reporting.human(
        _blank_report(verified=True, findings=[Finding("s", "R", "high", "m")]))
    check("unverified wording", "COULD NOT VERIFY" in unverified, True)
    check("and is not called a failure", "FAIL --" in unverified, False)
    check("failure wording", "FAIL --" in failed, True)


def test_human_report_marks_stages_that_did_not_run():
    text = reporting.human(_blank_report(verified=False))
    check("not-run stages are visible", "----" in text, True)


def test_report_json_round_trips():
    report = _blank_report(verified=True, findings=[Finding("s", "R", "low", "m")])
    parsed = json.loads(reporting.as_json(report))
    check("verified", parsed["verified"], True)
    check("stage count", len(parsed["stages"]), len(drill.STAGES))
    check("finding survives", parsed["findings"][0]["rule"], "R")


def test_report_never_prints_a_registered_secret():
    forget_secrets()
    register_secret("container-password-xyz")
    report = _blank_report(
        verified=True,
        findings=[Finding("s", "R", "high", "used container-password-xyz",
                          evidence="container-password-xyz")])
    for name, text in (("human", reporting.human(report)),
                       ("json", reporting.as_json(report))):
        check(f"{name} output is clean", "container-password-xyz" in text, False)
    forget_secrets()


# --------------------------------------------------------------------- cli --

def test_cli_exposes_no_credential_or_dsn_flags():
    """PLAN.md §7: /proc/*/cmdline is world-readable and CI logs echo commands."""
    help_text = _help_of(build_parser())
    for banned in ("--dsn", "--password", "--pgpassword", "--conn"):
        check(f"{banned} is absent", banned in help_text, False)


def _help_of(parser) -> str:
    out = io.StringIO()
    parser.print_help(out)
    for action in parser._subparsers._group_actions[0].choices.values():
        action.print_help(out)
    return out.getvalue()


def test_cli_default_image_is_not_alpine():
    """Alpine is musl; restoring a glibc dump into it breaks collation, which is
    the silent corruption the project exists to detect."""
    check("default image", docker.image_for("16"), "postgres:16")
    check("flavour is opt-in", docker.image_for("16", "-alpine"), "postgres:16-alpine")


def test_duration_parsing():
    check("seconds", _duration("90"), 90.0)
    check("s", _duration("90s"), 90.0)
    check("m", _duration("45m"), 2700.0)
    check("h", _duration("2h"), 7200.0)


def test_cli_run_on_missing_file_fails_loudly():
    from firedrill.cli import main
    code = main(["run", str(HERE / "definitely-not-here.dump"), "--quiet"])
    check("non-zero", code, 1)


# --------------------------------------------------------- integration ------
# These need Docker. They skip explicitly and are counted; CI passes
# --require-integration on Linux so a skip there fails the build.

def test_integration_healthy_pg16_is_silent():
    needs_docker()
    report = drill.run(corpus("healthy_pg16.dump"))
    check("verified", report.verified, True)
    check("zero findings on a healthy backup", [f.rule for f in report.findings], [])
    check("exit 0", report.exit_code, 0)
    check("restored into the matching major",
          report.archive["restored_into_major"], "16")


def test_integration_healthy_pg18_is_silent():
    needs_docker()
    report = drill.run(corpus("healthy_pg18.dump"))
    check("zero findings", [f.rule for f in report.findings], [])
    check("version matched", report.archive["restored_into_major"], "18")


def test_integration_truncated_data_is_caught():
    needs_docker()
    report = drill.run(corpus("truncated_data.dump"))
    check("verified -- it did reach a container", report.verified, True)
    check("rule", "ARCHIVE_TRUNCATED" in {f.rule for f in report.findings}, True)
    check("exit 1", report.exit_code, 1)


def test_integration_truncated_header_never_starts_a_container():
    needs_docker()
    report = drill.run(corpus("truncated_header.dump"))
    check("not verified", report.verified, False)
    check("rule", [f.rule for f in report.findings], ["ARCHIVE_UNREADABLE"])
    check("target stage did not run", report.stage("target").status, drill.NOT_RUN)


def test_integration_missing_role_is_caught():
    needs_docker()
    report = drill.run(corpus("missing_role.dump"))
    check("rule", "ROLE_ABSENT" in {f.rule for f in report.findings}, True)


def test_integration_empty_database_is_caught():
    """Restores perfectly and contains nothing -- a dump of the wrong database."""
    needs_docker()
    report = drill.run(corpus("empty_database.dump"))
    check("restore itself succeeded", report.stage("restore").status, drill.OK)
    check("but smoke caught it", "EMPTY_RESTORE" in {f.rule for f in report.findings}, True)
    check("exit 1", report.exit_code, 1)


def test_integration_plain_sql_is_rejected():
    needs_docker()
    report = drill.run(corpus("not_an_archive.sql"))
    check("rule", [f.rule for f in report.findings], ["ARCHIVE_UNREADABLE"])


def test_integration_leaves_no_containers_behind():
    needs_docker()
    before = set(docker.orphans())
    drill.run(corpus("healthy_pg16.dump"))
    check("teardown ran", set(docker.orphans()) - before, set())


def test_integration_container_password_is_not_on_the_command_line():
    needs_docker()
    container = docker.Container("16")
    container.start()
    try:
        container.wait_ready()
        listing = subprocess.run(["docker", "inspect", container.name],
                                 capture_output=True, text=True).stdout
        # It is legitimately in the container's own env; what must never happen
        # is it appearing in the arguments of a process on the host.
        host = subprocess.run(["ps", "-ax", "-o", "command"],
                              capture_output=True, text=True).stdout
        check("absent from host process arguments", container.password in host, False)
        check("the container did receive it", container.password in listing, True)
    finally:
        container.teardown()


def test_integration_dump_is_mounted_read_only():
    needs_docker()
    path = corpus("healthy_pg16.dump")
    before = path.read_bytes()
    container = docker.Container("16", dump=path)
    container.start()
    try:
        container.wait_ready()
        written = container.exec(
            ["sh", "-c", f"echo corrupt >> {docker.DUMP_PATH} && echo WROTE || echo REFUSED"])
        check("the container cannot write to the backup",
              "REFUSED" in written.stdout, True)
    finally:
        container.teardown()
    check("source bytes unchanged", path.read_bytes(), before)


def test_integration_docker_unavailable_reports_rather_than_passes():
    """The rule, exercised end to end: no daemon means no verification, not a pass."""
    needs_docker()
    import os
    saved = os.environ.get("DOCKER_HOST")
    os.environ["DOCKER_HOST"] = "unix:///firedrill-nonexistent.sock"
    try:
        report = drill.run(corpus("healthy_pg16.dump"))
    finally:
        if saved is None:
            os.environ.pop("DOCKER_HOST", None)
        else:
            os.environ["DOCKER_HOST"] = saved
    check("not verified", report.verified, False)
    check("rule", [f.rule for f in report.findings], ["TARGET_UNAVAILABLE"])
    check("non-zero exit", report.exit_code, 1)
    check("the message says it could not be verified",
          "could NOT be verified" in report.findings[0].message, True)


# -------------------------------------------------------------------- run --

def main() -> int:
    require_integration = "--require-integration" in sys.argv

    # Discovered, not listed. A hand-maintained roster silently stops running a
    # test the moment an edit drops a name.
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]

    # A floor, not a target. Edits that replace a range of lines have silently
    # swallowed whole blocks of tests before; the suite then goes green with
    # fewer tests and says nothing.
    FLOOR = 40
    if len(tests) < FLOOR:
        raise SystemExit(
            f"test suite shrank: {len(tests)} < {FLOOR}. An edit probably deleted "
            "tests -- check git diff."
        )

    for fn in tests:
        try:
            fn()
        except Skip as exc:
            SKIPPED.append(f"{fn.__name__}: {exc}")

    if FAILURES:
        print(f"FAIL ({len(FAILURES)})")
        print("\n".join(FAILURES))
        return 1

    if SKIPPED:
        print(f"skipped {len(SKIPPED)}:")
        for line in SKIPPED:
            print(f"  - {line}")
        if require_integration:
            print("\n--require-integration was passed and tests skipped. "
                  "On this platform they must run; a skip is not a pass.")
            return 1

    print(f"ok  ({len(tests)} tests, {CHECKS[0]} checks, {len(SKIPPED)} skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
