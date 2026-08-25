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
import time
import hashlib
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from firedrill import archive, config, docker, drill, report as reporting, restore
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


def test_human_report_renders_every_stage_status():
    """A KeyError here took out `firedrill run` on its default path -- no
    config means two rungs are 'not configured', and the reporter had no mark
    for it. The report is how every other failure gets communicated, so it is
    the last thing that may crash."""
    report = _blank_report(verified=True)
    statuses = [drill.OK, drill.FAILED, drill.NOT_RUN, drill.NOT_CONFIGURED,
                "a status from a later phase"]
    for stage, status in zip(report.stages, statuses):
        stage.status = status
    text = reporting.human(report)
    check("not configured is marked", "n/a" in text, True)
    check("an unknown status stays visible instead of crashing",
          "????" in text, True)


def test_human_report_prints_what_was_suppressed_and_why():
    """A green run must always show what was set aside to make it green."""
    report = _blank_report(verified=True)
    report.suppressed = [{"rule": "COLLATION_MISMATCH", "severity": "high",
                          "reason": "alpine vs debian, tracked in DR-114",
                          "message": "m"}]
    text = reporting.human(report)
    check("names the rule", "COLLATION_MISMATCH" in text, True)
    check("and prints the written reason", "DR-114" in text, True)


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


# -------------------------------------------------------------- config ------

GOOD_CONFIG = """
version: 1
target:
  type: docker
tier: full
rto_budget: 45m
structure:
  reference: schema/production.sql
volume:
  tables:
    orders: {min_rows: 1}
semantics:
  - name: recent orders exist
    sql: SELECT count(*) FROM orders WHERE created_at > now() - interval '7 days'
    expect: "> 0"
ignore:
  - check: COLLATION_MISMATCH
    reason: "tracked in DR-114"
"""


def _rejects(label: str, text: str, expect_phrase: str = ""):
    """Assert a config is refused, and that the message explains why."""
    try:
        config.loads(text)
    except config.ConfigError as exc:
        if expect_phrase:
            check(f"{label}: message explains", expect_phrase in str(exc), True)
        return
    FAILURES.append(f"  {label}\n    expected ConfigError\n    got      accepted")


def test_config_reads_the_documented_example():
    """The other direction. A loader that rejects PLAN.md §6's own example is
    exactly as broken as one that accepts nonsense."""
    cfg = config.loads(GOOD_CONFIG)
    check("tier", cfg.tier, "full")
    check("rto in seconds", cfg.rto_budget, 2700.0)
    # Compared as a path, not as a string: Windows renders the same Path as
    # 'schema\\production.sql', which is correct behaviour and a failing
    # string comparison. This is the sort of thing the Windows leg is for.
    check("reference", cfg.structure_reference,
          pathlib.Path("schema/production.sql"))
    check("per-table min_rows", cfg.volume_tables["orders"].min_rows, 1)
    check("one semantic check", len(cfg.semantics), 1)
    check("operator", cfg.semantics[0].op, ">")
    check("threshold", cfg.semantics[0].threshold, 0)
    check("ignore is recorded with its reason",
          cfg.ignore["COLLATION_MISMATCH"], "tracked in DR-114")


def test_config_semantic_check_evaluates_both_ways():
    cfg = config.loads(GOOD_CONFIG)
    rule = cfg.semantics[0]
    check("5 > 0 holds", rule.holds(5), True)
    check("0 > 0 does not", rule.holds(0), False)


def test_config_ignore_without_a_reason_is_an_error():
    """PLAN.md §6: an unexplained suppression is a config error, not a warning."""
    _rejects("no reason key", """
version: 1
ignore:
  - check: COLLATION_MISMATCH
""", "no written reason")
    _rejects("blank reason", """
version: 1
ignore:
  - check: COLLATION_MISMATCH
    reason: "   "
""", "no written reason")


def test_config_unknown_key_is_an_error_not_a_warning():
    """A typo'd key that loads silently means a check the user believes is
    running is not running, and the run still goes green."""
    _rejects("misspelled top level", """
version: 1
volumes:
  tolerance: 10%
""", "unknown key")
    _rejects("misspelled nested", """
version: 1
volume:
  tolerence: 10%
""", "unknown key")


def test_config_expect_must_be_a_comparison_not_a_row():
    """PLAN.md §7 enforced by the schema: there is no way to write a check
    whose result is echoed verbatim."""
    for bad in ("the newest order", "SELECT email FROM app_user", "> ", "0"):
        _rejects(f"expect {bad!r}", f"""
version: 1
semantics:
  - name: x
    sql: select count(*) from t
    expect: "{bad}"
""", "comparison against a number")


def test_config_refuses_multiple_statements_in_one_check():
    _rejects("two statements", """
version: 1
semantics:
  - name: x
    sql: "select count(*) from t; drop table t"
    expect: "> 0"
""", "more than one statement")


def test_config_trailing_semicolon_is_fine():
    """One statement written with a terminator is not two statements. Refusing
    it would be a false positive, which costs what a false negative costs."""
    cfg = config.loads("""
version: 1
semantics:
  - name: x
    sql: "select count(*) from t;"
    expect: ">= 1"
""")
    check("accepted", len(cfg.semantics), 1)
    check("terminator stripped", cfg.semantics[0].sql.endswith("t"), True)


def test_config_unimplemented_tier_is_refused_not_silently_upgraded():
    """A report saying 'fast' when a full restore ran is a lie about what was
    verified, and so is the reverse. `sample` is still unbuilt, so it is still
    refused by name rather than quietly promoted to something that does run."""
    check("fast is implemented and loads", config.loads(
        "version: 1\ntier: fast\n").tier, "fast")
    _rejects("nonsense", "version: 1\ntier: turbo\n", "must be one of")
    check("sample is implemented and loads", config.loads(
        "version: 1\ntier: sample\nsample:\n  tables: [t]\n").tier, "sample")


def test_config_dsn_target_is_refused_until_its_interlocks_exist():
    _rejects("dsn", "version: 1\ntarget:\n  type: dsn\n", "four interlocks")


def test_config_version_must_be_stated():
    _rejects("missing", "tier: full\n", "version")
    _rejects("wrong", "version: 2\n", "version")


def test_config_empty_file_is_an_error():
    _rejects("empty", "\n", "empty")


def test_config_tolerance_now_that_history_gives_it_a_baseline():
    """This was refused for two phases, because a tolerance needs something to
    be tolerant *of* and nothing recorded one. history.json does now, so the
    key is read rather than refused -- and the refusal was removed in the same
    commit that made it readable, not before."""
    cfg = config.loads(
        "version: 1\nvolume:\n  tolerance: 10%\n"
        "  tables:\n    orders: {tolerance: 50%}\n")
    check("global tolerance", cfg.volume_tolerance, 0.10)
    check("per-table overrides it", cfg.volume_tables["orders"].tolerance, 0.50)
    check("still refuses a bare number",
          config.parse_percent("50%"), 0.50)
    _rejects("bare number is still ambiguous",
             "version: 1\nvolume:\n  tolerance: 10\n", "ambiguous")


def test_config_empty_table_rule_is_an_error():
    _rejects("checks nothing", """
version: 1
volume:
  tables:
    orders: {}
""", "checks nothing")


def test_config_duplicate_semantic_names_are_refused():
    _rejects("same name twice", """
version: 1
semantics:
  - {name: x, sql: select 1, expect: "> 0"}
  - {name: x, sql: select 2, expect: "> 0"}
""", "ambiguous")


def test_pyproject_table_ordering_cannot_swallow_the_urls():
    """A regression test for a bug no other test here could see.

    `urls.Source = ...` are bare keys in the [project] table. Opening
    [project.optional-dependencies] above them silently reparents them into
    it, and the package then fails to build -- while the whole suite still
    passes, because the suite imports the source tree and never builds it.

    Checked by string position rather than tomllib, which is 3.11+ and this
    project's floor is 3.10. A skip here would fail CI anyway, by design.
    """
    text = (HERE.parent / "pyproject.toml").read_text(encoding="utf-8")
    extras = text.find("[project.optional-dependencies]")
    check("the extras table exists", extras > 0, True)
    for key in ("urls.Source", "urls.Issues", "urls.Changelog"):
        position = text.find(key)
        check(f"{key} is declared", position > 0, True)
        check(f"{key} is above the extras table, not captured by it",
              position < extras, True)


def test_action_yml_passes_only_flags_the_cli_actually_has():
    """The GitHub Action and the CLI drift apart silently otherwise.

    A renamed flag would make the action fail at run time, in somebody else's
    nightly job, with a message about an unrecognised argument -- and the
    build would go red for a reason that has nothing to do with their backup.
    """
    import re
    text = (HERE.parent / "action.yml").read_text(encoding="utf-8")
    used = set()
    for line in text.splitlines():
        if "args+=(" in line:
            used.update(re.findall(r"--[a-z][a-z-]*", line))
    check("the action passes some flags", len(used) >= 5, True)

    known = set()
    for action in build_parser()._subparsers._group_actions[0].choices["run"]._actions:
        known.update(action.option_strings)
    missing = sorted(used - known)
    check(f"every flag exists in `firedrill run` (missing: {missing})", missing, [])


def test_action_shell_scripts_are_valid_bash():
    """A syntax error in a composite action is discovered by whoever runs it,
    in their CI, not ours -- unless it is checked here.

    This also pins the heredoc inside it: `<<'PY'` needs its terminator at
    column zero, and YAML block-scalar stripping is what decides whether it
    lands there. Re-indenting the surrounding block would silently break it.
    """
    import shutil
    import yaml as yaml_module
    if shutil.which("bash") is None:
        raise Skip("bash is not available on this platform")

    action = yaml_module.safe_load(
        (HERE.parent / "action.yml").read_text(encoding="utf-8"))
    steps = [s for s in action["runs"]["steps"] if s.get("shell") == "bash"]
    check("the action has bash steps", len(steps) >= 3, True)
    for step in steps:
        # GitHub expressions are not bash; substitute a literal so the shell
        # sees the shape of the script rather than the templating.
        import re
        script = re.sub(r"\$\{\{[^}]*\}\}", "x", step["run"])
        result = subprocess.run(["bash", "-n"], input=script,
                                capture_output=True, text=True)
        check(f"{step.get('name', '?')!r} parses",
              (result.returncode, result.stderr.strip()), (0, ""))

    drill_step = [s for s in steps if s.get("id") == "drill"][0]
    terminators = [l for l in drill_step["run"].splitlines() if l.strip() == "PY"]
    check("the heredoc terminator survives at column 0",
          terminators and terminators[0] == "PY", True)


def test_ci_exercises_the_action_it_ships():
    """Phase 0's CI workflows sat unrun until something was pushed, and the
    first execution found a real bug. The action is the same kind of artefact,
    so the workflow that runs it is pinned here rather than hoped for."""
    import yaml as yaml_module
    ci = yaml_module.safe_load(
        (HERE.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    check("there is a job for it", "action" in ci["jobs"], True)
    steps = ci["jobs"]["action"]["steps"]
    uses_local = [s for s in steps if s.get("uses") == "./"]
    check("it runs the action from this checkout", len(uses_local) >= 3, True)
    check("including a healthy backup", any(
        "healthy" in str(s.get("with", {}).get("dump", "")) for s in uses_local), True)
    check("and a broken one, which matters exactly as much", any(
        "truncated" in str(s.get("with", {}).get("dump", "")) for s in uses_local), True)


def test_example_workflows_parse_and_pin_their_intent():
    """They are the phase's deliverable -- a stranger copies these."""
    import yaml as yaml_module
    examples = sorted((HERE.parent / "examples").glob("*.yml"))
    check("examples exist", len(examples) >= 2, True)
    for path in examples:
        loaded = yaml_module.safe_load(path.read_text(encoding="utf-8"))
        check(f"{path.name} is valid yaml", isinstance(loaded, dict), True)
        check(f"{path.name} has jobs", "jobs" in loaded, True)
        # `on:` is the YAML 1.1 boolean True, which is a classic footgun and
        # worth pinning: if this ever parses as the string "on", the file was
        # quoted differently and the trigger may not be what it looks like.
        check(f"{path.name} declares a trigger", True in loaded or "on" in loaded, True)


def test_junit_distinguishes_skipped_from_passed():
    """Most CI dashboards colour skipped differently from passed, which is the
    one distinction this whole tool exists to preserve."""
    import xml.etree.ElementTree as ET
    report = _blank_report(verified=True)
    report.stages[0].status = drill.OK
    report.stages[1].status = drill.FAILED
    report.stages[2].status = drill.NOT_RUN
    report.stages[3].status = drill.NOT_CONFIGURED
    report.findings.append(Finding(report.stages[1].name, "R", "high", "m", "f"))

    root = ET.fromstring(reporting.as_junit(report))
    kinds = {c.get("name"): (c[0].tag if len(c) else "pass") for c in root}
    check("ok is a pass", kinds[report.stages[0].name], "pass")
    check("failed is a failure", kinds[report.stages[1].name], "failure")
    check("not run is skipped", kinds[report.stages[2].name], "skipped")
    check("not configured is skipped", kinds[report.stages[3].name], "skipped")


def test_junit_marks_an_unverified_run_as_failing():
    """'Could not verify' must not read as 'nothing to report'."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(reporting.as_junit(_blank_report(verified=False)))
    names = [c.get("name") for c in root]
    check("a verified case is added", "verified" in names, True)
    case = [c for c in root if c.get("name") == "verified"][0]
    check("and it fails", case[0].tag, "failure")


def test_history_records_no_data_from_inside_the_database():
    """A history file is the artefact of this tool most likely to be committed
    to a repo, so its field set is pinned exactly like Finding's."""
    from firedrill import history
    report = _blank_report(verified=True)
    report.row_counts = {"customer": 2000}
    entry = history._entry(report)
    check("field set", sorted(entry), [
        "at", "dump", "findings", "ok", "row_counts", "server_major",
        "server_version", "size_bytes", "stages", "tier", "total_seconds",
        "verified"])
    check("counts are aggregates", entry["row_counts"], {"customer": 2000})


def test_history_last_good_will_not_cross_tiers():
    """A fast run records no row counts and a sample run only some. Comparing
    a full run against either would invent a loss that never happened."""
    from firedrill import history
    entries = [
        {"ok": True, "verified": True, "tier": "full", "total_seconds": 10.0},
        {"ok": True, "verified": True, "tier": "fast", "total_seconds": 1.0},
        {"ok": False, "verified": True, "tier": "full", "total_seconds": 99.0},
    ]
    check("newest passing full run", history.last_good(entries, "full")["total_seconds"], 10.0)
    check("fast is matched separately", history.last_good(entries, "fast")["total_seconds"], 1.0)
    check("a failed run is never a baseline",
          history.last_good(entries, "full")["total_seconds"] != 99.0, True)
    check("nothing to compare against yet", history.last_good([], "full"), None)
    check("and trend says nothing rather than guessing",
          history.trend([], 5.0, "full"), "")


def test_readme_yaml_examples_actually_load():
    """Config documentation that does not parse is worse than none: it costs a
    reader their time and their trust.

    The README also contains GitHub workflow snippets, which are yaml but not
    firedrill config. They are told apart by content rather than by being
    exempted by position -- a config example that forgets `version: 1` must
    still fail here, which it has done twice.
    """
    import re
    import yaml as yaml_module
    readme = (HERE.parent / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", readme, re.S)
    check("the README documents at least one yaml block", len(blocks) >= 1, True)

    configs = 0
    for index, block in enumerate(blocks):
        if "uses:" in block or "jobs:" in block:
            # A workflow snippet: it only has to be valid yaml.
            try:
                yaml_module.safe_load(block)
                CHECKS[0] += 1
            except yaml_module.YAMLError as exc:
                FAILURES.append(f"  README workflow block {index} is not yaml\n    {exc}")
            continue
        configs += 1
        try:
            config.loads(block)
            CHECKS[0] += 1
        except config.ConfigError as exc:
            FAILURES.append(f"  README config block {index} does not load\n    {exc}")
    check("and at least one of them is a firedrill config", configs >= 1, True)


def test_config_defaults_when_there_is_no_file():
    cfg = config.DEFAULT
    check("tier", cfg.tier, "full")
    check("no semantics", cfg.semantics, ())
    check("nothing ignored", cfg.is_ignored("ANYTHING"), False)


# ------------------------------------------------- the availability probe ---
# `docker info` does not answer "can you run a linux postgres container?", and
# these three pin the gap between what it reports and what we need to know.
# Found by the first CI run on a real ubuntu-24.04 runner, where an unreachable
# daemon exited 0 and the probe called it usable.

def _stub_docker_info(returncode: int, stdout: str):
    """Replace docker._run for one probe call. Returns the restore callable."""
    original = docker._run
    docker._run = lambda *a, **k: subprocess.CompletedProcess(
        args=["docker", "info"], returncode=returncode, stdout=stdout, stderr=""
    )
    return lambda: setattr(docker, "_run", original)


def test_probe_rejects_an_empty_server_version():
    """Exit code 0 with no server version is a dead daemon, not a live one."""
    restore_run = _stub_docker_info(0, "|linux\n")
    try:
        usable, why = docker.docker_available()
    finally:
        restore_run()
    check("not usable", usable, False)
    check("and says why", "no server version" in why, True)


def test_probe_rejects_windows_container_mode():
    """A Windows daemon answers happily and cannot pull a linux image."""
    restore_run = _stub_docker_info(0, "29.1.2|windows\n")
    try:
        usable, why = docker.docker_available()
    finally:
        restore_run()
    check("not usable", usable, False)
    check("names the mode", "windows-container mode" in why, True)


def test_probe_accepts_a_linux_daemon():
    """The other direction, which costs exactly as much to get wrong: a healthy
    linux daemon must not be rejected, or every restore silently stops running."""
    restore_run = _stub_docker_info(0, "29.1.2|linux\n")
    try:
        usable, why = docker.docker_available()
    finally:
        restore_run()
    check("usable", usable, True)
    check("reports the server version", why, "29.1.2")


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


def test_integration_probe_reads_a_real_daemon():
    """The stubs above prove the branching; this proves the format string still
    parses on a real `docker info`. A typo there would make every probe return
    an empty server version and skip every restore -- green, and worthless."""
    needs_docker()
    usable, why = docker.docker_available()
    check("a real daemon is usable", usable, True)
    check("and the reason field carries a version, not an empty string",
          bool(why.strip()), True)


# The Phase 1 ladder, asserted against real broken backups. Every fixture
# below restores with zero pg_restore findings -- that is measured, not
# assumed -- so each of these is a failure that only a restored database can
# show you.

LADDER_CONFIG = """
version: 1
volume:
  tables:
    customer: {min_rows: 1000}
semantics:
  - name: recent customers exist
    sql: select count(*) from customer where created_at > now() - interval '7 days'
    expect: "> 0"
"""


def _ladder_run(fixture: str):
    return drill.run(corpus(fixture), cfg=config.loads(LADDER_CONFIG))


def test_integration_healthy_passes_every_rung():
    """The most important assertion in the suite. A DR tool that cries wolf
    gets muted, and a muted DR tool is worse than none."""
    needs_docker()
    report = _ladder_run("healthy_pg16.dump")
    check("zero findings", [f.rule for f in report.findings], [])
    check("exit 0", report.exit_code, 0)
    for rung in ("volume", "semantics", "integrity"):
        check(f"{rung} ran and passed", report.stage(rung).status, drill.OK)


def test_integration_volume_drop_is_caught_by_volume_alone():
    """99% of rows gone. Restores clean, passes every structural check."""
    needs_docker()
    report = _ladder_run("volume_drop.dump")
    check("rule", [f.rule for f in report.findings], ["VOLUME_BELOW_MINIMUM"])
    check("volume failed", report.stage("volume").status, drill.FAILED)
    check("and the other rungs did not", report.stage("semantics").status, drill.OK)
    check("nor integrity", report.stage("integrity").status, drill.OK)
    check("exit 1", report.exit_code, 1)


def test_integration_stale_replica_is_caught_by_semantics_alone():
    """PLAN.md §8: the fixture that justifies the whole project. The schema is
    right, the row count is right, and the data is a year old."""
    needs_docker()
    report = _ladder_run("stale_replica.dump")
    check("rule", [f.rule for f in report.findings], ["SEMANTICS_FAILED"])
    check("volume is satisfied", report.stage("volume").status, drill.OK)
    check("integrity is satisfied", report.stage("integrity").status, drill.OK)
    check("only semantics caught it", report.stage("semantics").status, drill.FAILED)


def test_integration_sequence_behind_is_caught_by_integrity_alone():
    """setval below max(id): the first insert after failover raises a
    duplicate key, and nothing before this rung would have told you."""
    needs_docker()
    report = _ladder_run("sequence_behind.dump")
    check("rule", [f.rule for f in report.findings], ["SEQUENCE_BEHIND"])
    check("integrity failed", report.stage("integrity").status, drill.FAILED)
    check("volume is satisfied", report.stage("volume").status, drill.OK)
    check("semantics is satisfied", report.stage("semantics").status, drill.OK)


def test_integration_unconfigured_rungs_say_so_rather_than_passing():
    """With no config, volume and semantics have nothing to check. They must
    report 'not configured', which is not a tick."""
    needs_docker()
    report = drill.run(corpus("healthy_pg16.dump"))
    check("volume", report.stage("volume").status, drill.NOT_CONFIGURED)
    check("semantics", report.stage("semantics").status, drill.NOT_CONFIGURED)
    check("integrity needs no config and still runs",
          report.stage("integrity").status, drill.OK)
    check("and the run is still green", report.exit_code, 0)


def test_integration_ignore_suppresses_with_its_reason_recorded():
    """A suppressed finding is moved aside under its written reason, not
    deleted. The config must not be a way to make problems invisible."""
    needs_docker()
    cfg = config.loads(LADDER_CONFIG + """
ignore:
  - check: VOLUME_BELOW_MINIMUM
    reason: "this fixture is deliberately small; tracked in TEST-1"
""")
    report = drill.run(corpus("volume_drop.dump"), cfg=cfg)
    check("no findings remain", [f.rule for f in report.findings], [])
    check("exit 0 now", report.exit_code, 0)
    check("but it is recorded", [s["rule"] for s in report.suppressed],
          ["VOLUME_BELOW_MINIMUM"])
    check("with the reason", "TEST-1" in report.suppressed[0]["reason"], True)


def test_integration_cli_config_changes_the_verdict_and_a_typo_does_not():
    """Three runs of one backup, which together are the argument for the whole
    config file: configured, it is caught; unconfigured, the same broken
    backup exits 0; and a typo'd config is refused rather than silently
    degrading into that second case."""
    needs_docker()
    import tempfile
    from firedrill.cli import main
    fixture = str(corpus("stale_replica.dump"))
    with tempfile.TemporaryDirectory() as tmp:
        good = pathlib.Path(tmp) / "firedrill.yml"
        good.write_text(LADDER_CONFIG.replace(
            "min_rows: 1000", "min_rows: 1"), encoding="utf-8")
        bad = pathlib.Path(tmp) / "bad.yml"
        bad.write_text("version: 1\nvolume:\n  tolerence: 10%\n", encoding="utf-8")

        check("configured: caught",
              main(["run", fixture, "--quiet", "--config", str(good)]), 1)
        check("unconfigured: the same backup looks fine",
              main(["run", fixture, "--quiet", "--no-config"]), 0)
        check("a typo'd config is refused, not degraded",
              main(["run", fixture, "--quiet", "--config", str(bad)]), 2)


def _reference_for(fixture: str, tmp) -> pathlib.Path:
    ref = pathlib.Path(tmp) / "reference.txt"
    drill.run(corpus(fixture), write_reference=ref)
    return ref


def test_integration_structure_reference_covers_every_object_kind():
    """Every branch of the snapshot union must be present.

    This is a regression test for a silent one: the SQL was collapsed onto a
    single line before being sent, so a `--` comment inside it commented out
    the rest of the query. Whole branches vanished, and the result was still
    valid rows that compared equal to themselves -- green, and blind.
    """
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        text = _reference_for("healthy_pg16.dump", tmp).read_text()
        for kind in ("column", "index", "constraint", "sequence", "extension"):
            check(f"{kind} rows survive", any(
                line.startswith(kind + "|") for line in text.splitlines()), True)
        check("and nothing internal leaks in", "pg_toast" in text, False)


def test_integration_structure_reference_is_portable_across_majors():
    """One committed reference, two major versions. PG18 materialises NOT NULL
    as pg_constraint rows and PG16 does not; if the snapshot included them,
    every not-null column would report as drift after a major upgrade."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = _reference_for("healthy_pg16.dump", tmp)
        cfg = config.loads(f"version: 1\nstructure:\n  reference: {ref}\n")
        for fixture in ("healthy_pg16.dump", "healthy_pg18.dump"):
            report = drill.run(corpus(fixture), cfg=cfg)
            check(f"{fixture} is clean against a pg16 reference",
                  [f.rule for f in report.findings], [])


def test_integration_missing_index_is_caught_by_structure_alone():
    """Right rows, right data, right sequences -- only the catalog differs."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = _reference_for("healthy_pg16.dump", tmp)
        cfg = config.loads(
            f"version: 1\nstructure:\n  reference: {ref}\n" + LADDER_CONFIG.split("\n", 2)[2]
        )
        report = drill.run(corpus("missing_index.dump"), cfg=cfg)
        check("rule", [f.rule for f in report.findings], ["STRUCTURE_MISSING"])
        check("structure failed", report.stage("structure").status, drill.FAILED)
        check("volume is satisfied", report.stage("volume").status, drill.OK)
        check("semantics is satisfied", report.stage("semantics").status, drill.OK)
        check("integrity is satisfied", report.stage("integrity").status, drill.OK)


def test_integration_absent_reference_is_reported_not_passed():
    """A comparison that could not happen is not a comparison that passed."""
    needs_docker()
    cfg = config.loads(
        "version: 1\nstructure:\n  reference: /firedrill-no-such-reference.txt\n")
    report = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
    check("rule", [f.rule for f in report.findings],
          ["STRUCTURE_REFERENCE_UNREADABLE"])
    check("non-zero exit", report.exit_code, 1)


def test_integration_write_reference_does_not_also_compare():
    """Regenerating the reference in the same run that is judged against it
    would be a check that can never fail."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = pathlib.Path(tmp) / "r.txt"
        cfg = config.loads(f"version: 1\nstructure:\n  reference: {ref}\n")
        report = drill.run(corpus("missing_index.dump"), cfg=cfg, write_reference=ref)
        check("it wrote", ref.exists(), True)
        check("and did not compare against what it just wrote",
              [f.rule for f in report.findings], [])
        check("the detail says so", "wrote" in report.stage("structure").detail, True)


def test_integration_collation_is_silent_on_a_matching_libc():
    """PLAN.md §3.4 is the loudest check in the tool, which makes a false
    positive here especially expensive. The default Debian target matches the
    reference it wrote, so it must say nothing at all."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = _reference_for("healthy_pg16.dump", tmp)
        check("the reference records a collation",
              any(l.startswith("collation|") for l in ref.read_text().splitlines()),
              True)
        cfg = config.loads(f"version: 1\nstructure:\n  reference: {ref}\n")
        report = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
        check("nothing at all", [f.rule for f in report.findings], [])


def test_integration_musl_target_is_caught_as_both_unverifiable_and_mismatched():
    """Measured, not assumed: a musl target reports an EMPTY collation
    version, not a different one. Restoring a glibc-referenced dump there is
    the silent corruption of §3.4 -- text indexes sort differently, queries
    return wrong rows, and nothing raises an error."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = _reference_for("healthy_pg16.dump", tmp)
        cfg = config.loads(f"version: 1\nstructure:\n  reference: {ref}\n")
        report = drill.run(corpus("healthy_pg16.dump"), cfg=cfg, flavour="-alpine")
        rules = {f.rule for f in report.findings}
        check("the target cannot answer the question",
              "COLLATION_UNVERIFIABLE" in rules, True)
        check("and it differs from the reference",
              "COLLATION_MISMATCH" in rules, True)
        check("non-zero exit", report.exit_code, 1)
        check("the structure rung does not also report it as generic drift",
              "STRUCTURE_UNEXPECTED" in rules or "STRUCTURE_MISSING" in rules, False)


def test_integration_unverifiable_collation_needs_no_reference():
    """The honest half of the check works with no baseline at all: a target
    that cannot report a collation version cannot prove sort order either."""
    needs_docker()
    report = drill.run(corpus("healthy_pg16.dump"), flavour="-alpine")
    rules = {f.rule for f in report.findings}
    check("still reported", "COLLATION_UNVERIFIABLE" in rules, True)
    check("but no mismatch is claimed without a baseline",
          "COLLATION_MISMATCH" in rules, False)


def test_integration_missing_extension_is_caught():
    """PLAN.md §3.3's other half, and the last §8 fixture.

    The Phase 0 classifier carried an EXTENSION_ABSENT pattern that no fixture
    had ever exercised. This is the first time it has been shown to fire
    against a real pg_restore, on a target image whose hstore control file has
    been removed -- which is what a real recovery host without the binaries
    actually looks like.
    """
    needs_docker()
    import make_corpus
    report = drill.run(corpus("missing_extension.dump"),
                       flavour=make_corpus.NOEXT_FLAVOUR)
    rules = {f.rule for f in report.findings}
    check("caught", "EXTENSION_ABSENT" in rules, True)
    check("non-zero exit", report.exit_code, 1)
    check("and the dependent objects are reported too, not swallowed",
          "EMPTY_RESTORE" in rules, True)


def test_integration_extension_present_is_silent():
    """The same dump against a target that does have hstore. If this ever
    reports EXTENSION_ABSENT the check is worthless, because the finding would
    no longer mean the extension is missing."""
    needs_docker()
    report = drill.run(corpus("missing_extension.dump"))
    check("nothing", [f.rule for f in report.findings], [])
    check("exit 0", report.exit_code, 0)


def test_integration_restored_into_major_is_measured_not_assumed():
    """The report used to echo the major it *intended* to start. The image tag
    makes that true in practice, but 'the version we asked for' and 'the
    version that restored the dump' are different claims, and a report should
    only make the one it measured."""
    needs_docker()
    report = drill.run(corpus("healthy_pg18.dump"))
    check("asked for 18", report.archive["target_major_requested"], "18")
    check("and the server said 18", report.archive["restored_into_major"], "18")


def test_integration_pinning_an_older_major_is_caught_before_the_restore():
    """PLAN.md §8's wrong_major_version. It always failed; it just failed as a
    generic 'could not execute query' several stages later, which does not
    tell you that the pin was the problem."""
    needs_docker()
    report = drill.run(corpus("healthy_pg18.dump"), pin_major="16")
    findings = {f.rule: f for f in report.findings}
    check("named", "VERSION_MISMATCH" in findings, True)
    check("high -- a newer dump cannot restore into an older major",
          findings["VERSION_MISMATCH"].severity, "high")
    check("caught at inspect, before a container was started",
          findings["VERSION_MISMATCH"].stage, "inspect")
    check("and the restore does indeed fail", report.exit_code, 1)


def test_integration_pinning_a_newer_major_is_noted_but_not_fatal():
    """Restoring forward usually works, so this is medium and the restore
    still succeeds -- but it is not the version a real recovery would use, so
    it is not silent either."""
    needs_docker()
    report = drill.run(corpus("healthy_pg16.dump"), pin_major="18")
    check("rule", [f.rule for f in report.findings], ["VERSION_MISMATCH"])
    check("medium", report.findings[0].severity, "medium")
    check("the restore itself was fine", report.stage("restore").status, drill.OK)


def test_version_compare_handles_pre_10_majors():
    """Majors are '16' and '18', but pre-10 releases are '9.6'. Compared
    component-wise, because int('9.6') raises and a guess here would put a
    severity on a finding nobody measured."""
    check("9.6 is older than 10", drill._is_older("9.6", "10"), True)
    check("16 is older than 18", drill._is_older("16", "18"), True)
    check("18 is not older than 16", drill._is_older("18", "16"), False)
    check("unparseable does not guess", drill._is_older("nonsense", "18"), False)


def test_integration_fast_tier_never_looks_like_a_full_pass():
    """PLAN.md §3.5, stated as an experiment on one backup.

    stale_replica fails semantics on a full run. On a fast run the rows were
    never restored, so the honest outcome is NOT RUN -- not a failure, and
    emphatically not a tick. The whole point is that a reader can tell the two
    greens apart.
    """
    needs_docker()
    full = drill.run(corpus("stale_replica.dump"),
                     cfg=config.loads(LADDER_CONFIG))
    check("a full run catches it", [f.rule for f in full.findings],
          ["SEMANTICS_FAILED"])

    fast = drill.run(corpus("stale_replica.dump"),
                     cfg=config.loads("tier: fast\n" + LADDER_CONFIG))
    check("volume did not run", fast.stage("volume").status, drill.NOT_RUN)
    check("semantics did not run", fast.stage("semantics").status, drill.NOT_RUN)
    check("and neither is recorded as ok",
          drill.OK in (fast.stage("volume").status, fast.stage("semantics").status),
          False)

    text = reporting.human(fast)
    check("the tier is stated in capitals, unmissably", "tier: FAST" in text, True)
    check("the verdict does not claim the data was checked",
          "PASS (fast tier)" in text, True)
    check("and says so in as many words", "was not checked" in text, True)
    check("the json carries it too", json.loads(reporting.as_json(fast))["tier"],
          "fast")


def test_integration_fast_tier_still_restores_the_schema():
    """It is a cheaper check, not a fake one: the objects must really come
    back, and the catalog rungs that do not need rows must really run."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ref = _reference_for("healthy_pg16.dump", tmp)
        cfg = config.loads(
            f"version: 1\ntier: fast\nstructure:\n  reference: {ref}\n")
        report = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
        check("structure ran on a schema-only restore",
              report.stage("structure").status, drill.OK)
        check("collation still ran", report.stage("integrity").status, drill.OK)
        check("and said sequences were not part of it",
              "collation only" in report.stage("integrity").detail, True)
        check("naming the reason specific to this tier",
              "restored no rows" in report.stage("integrity").detail, True)
        check("no findings", [f.rule for f in report.findings], [])


def test_integration_fast_tier_misses_what_it_says_it_misses():
    """The inverse, so the previous test cannot pass by accident: a fast run
    of a backup whose ROWS are wrong must find nothing, because it never
    looked. If this ever fails, fast is secretly restoring data."""
    needs_docker()
    report = drill.run(corpus("volume_drop.dump"),
                       cfg=config.loads("tier: fast\n" + LADDER_CONFIG))
    check("nothing found", [f.rule for f in report.findings], [])
    check("because the rung did not run",
          report.stage("volume").status, drill.NOT_RUN)


# ------------------------------------------------------------- sources -----
# PLAN.md §9 Phase 2's exit condition is "runs against a real bucket with
# read-only credentials". A real AWS bucket is not something a test suite may
# create, so these run against MinIO: a real S3 server speaking the real
# protocol over a real socket, with credentials taken from the environment
# exactly as §7 requires. What that does NOT prove is AWS-specific IAM
# behaviour, and this comment is here so nobody later mistakes one for the
# other.

import contextlib


@contextlib.contextmanager
def _minio():
    """A throwaway S3 server, torn down in a finally like everything else."""
    import uuid
    name = f"firedrill-minio-{uuid.uuid4().hex[:8]}"
    started = subprocess.run(
        ["docker", "run", "-d", "--name", name, "--label", "firedrill=1",
         "-e", "MINIO_ROOT_USER=firedrilltest",
         "-e", "MINIO_ROOT_PASSWORD=firedrilltest-secret",
         "-p", "0:9000", "minio/minio", "server", "/data"],
        capture_output=True, text=True)
    if started.returncode != 0:
        raise Skip(f"could not start minio: {started.stderr.strip()[:120]}")
    try:
        mapped = subprocess.run(["docker", "port", name, "9000/tcp"],
                                capture_output=True, text=True).stdout.strip()
        endpoint = f"http://127.0.0.1:{mapped.splitlines()[0].rsplit(':', 1)[1]}"
        import os
        import boto3
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "firedrilltest")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "firedrilltest-secret")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
        client = boto3.client("s3", endpoint_url=endpoint)
        for _ in range(120):
            try:
                client.list_buckets()
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise Skip("minio never became ready")
        yield endpoint, client
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


def _needs_boto3():
    try:
        import boto3  # noqa: F401
    except ModuleNotFoundError:
        raise Skip("boto3 is not installed; the s3 source is an optional extra")


def _s3_cfg(endpoint: str, extra: str) -> str:
    return (f"version: 1\nsource:\n  type: s3\n  bucket: backups\n"
            f"  endpoint_url: {endpoint}\n{extra}")


def test_integration_s3_source_against_a_real_bucket():
    needs_docker()
    _needs_boto3()
    with _minio() as (endpoint, client):
        client.create_bucket(Bucket="backups")
        dump = corpus("healthy_pg16.dump")
        client.upload_file(str(dump), "backups", "postgres/daily/2026-08-24.dump")
        time.sleep(1.1)   # LastModified has one-second resolution
        client.upload_file(str(dump), "backups", "postgres/daily/2026-08-25.dump")
        digest = hashlib.sha256(dump.read_bytes()).hexdigest()

        explicit = drill.run(cfg=config.loads(_s3_cfg(
            endpoint, "  key: postgres/daily/2026-08-24.dump\n")))
        check("an explicit key restores", explicit.exit_code, 0)
        check("and the report names the object, not a temp path",
              explicit.dump, "s3://backups/postgres/daily/2026-08-24.dump")

        newest = drill.run(cfg=config.loads(_s3_cfg(
            endpoint, "  prefix: postgres/daily/\n  select: newest\n")))
        check("newest picks the later object",
              newest.dump, "s3://backups/postgres/daily/2026-08-25.dump")
        check("and it restores", newest.exit_code, 0)

        good = drill.run(cfg=config.loads(_s3_cfg(
            endpoint,
            f"  key: postgres/daily/2026-08-25.dump\n  sha256: {digest}\n")))
        check("a matching checksum passes", good.exit_code, 0)
        check("and the stage says it was verified",
              "sha256 verified" in good.stage("fetch").detail, True)


def test_integration_s3_failures_are_never_a_pass():
    """A backup that cannot be fetched is not a backup. Each of these must
    report, and none of them may reach a container."""
    needs_docker()
    _needs_boto3()
    with _minio() as (endpoint, client):
        client.create_bucket(Bucket="backups")
        client.upload_file(str(corpus("healthy_pg16.dump")), "backups", "b.dump")

        for label, extra in (
            ("a checksum that does not match", f"  key: b.dump\n  sha256: {'c' * 64}\n"),
            ("an object that is not there", "  key: nope.dump\n"),
            ("a prefix with nothing under it", "  prefix: empty/\n"),
        ):
            report = drill.run(cfg=config.loads(_s3_cfg(endpoint, extra)))
            check(f"{label}: reported", [f.rule for f in report.findings],
                  ["FETCH_FAILED"])
            check(f"{label}: non-zero", report.exit_code, 1)
            check(f"{label}: no container was started",
                  report.stage("target").status, drill.NOT_RUN)
            check(f"{label}: and it is not 'verified'", report.verified, False)


def test_integration_https_source_and_its_checksums():
    """One implementation covers every provider's presigned-URL case."""
    needs_docker()
    import functools
    import http.server
    import socketserver
    import threading

    root = str(CORPUS.resolve())
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)

    class Server(socketserver.TCPServer):
        allow_reuse_address = True

        def log_message(self, *a):  # pragma: no cover
            pass

    dump = corpus("healthy_pg16.dump")
    server = Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/healthy_pg16.dump"
        digest = hashlib.sha256(dump.read_bytes()).hexdigest()

        good = drill.run(cfg=config.loads(
            f"version: 1\nsource:\n  type: https\n  url: {url}\n"
            f"  sha256: {digest}\n  size: {dump.stat().st_size}\n"))
        check("fetched and restored", good.exit_code, 0)
        check("the origin has no query string in it", "?" in good.dump, False)

        for label, extra in (("checksum", f"  sha256: {'b' * 64}\n"),
                             ("size", "  size: 999999\n")):
            bad = drill.run(cfg=config.loads(
                f"version: 1\nsource:\n  type: https\n  url: {url}\n{extra}"))
            check(f"a wrong {label} is caught at the door",
                  [f.rule for f in bad.findings], ["FETCH_FAILED"])
            check(f"a wrong {label} never reaches a container",
                  bad.stage("target").status, drill.NOT_RUN)

        missing = drill.run(cfg=config.loads(
            f"version: 1\nsource:\n  type: https\n"
            f"  url: http://127.0.0.1:{server.server_address[1]}/nope.dump\n"))
        check("404 is reported", [f.rule for f in missing.findings], ["FETCH_FAILED"])
    finally:
        server.shutdown()


def test_plain_http_to_a_remote_host_is_refused():
    """A presigned URL's signature IS a credential and lives in the query
    string, so plain http would put a working one on the wire in clear text."""
    report = drill.run(cfg=config.loads(
        "version: 1\nsource:\n  type: https\n  url: http://s3.example.com/b.dump\n"))
    check("refused", [f.rule for f in report.findings], ["FETCH_FAILED"])
    check("and says why", "clear text" in report.findings[0].message, True)


def test_source_origin_never_carries_a_signature():
    """The unit-level guarantee behind the test above."""
    from firedrill import sources
    signed = ("https://bucket.s3.amazonaws.com/db.dump"
              "?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAREAL")
    safe = sources._safe_origin(signed)
    check("path kept", safe, "https://bucket.s3.amazonaws.com/db.dump")
    for secret in ("X-Amz-Signature", "deadbeef", "AKIAREAL", "?"):
        check(f"{secret} is gone", secret in safe, False)


def test_a_dump_path_and_a_configured_source_is_refused():
    """Guessing which backup was meant is the one thing a restore tool must
    never do."""
    report = drill.run(corpus("healthy_pg16.dump") if CORPUS.exists() else "x.dump",
                       cfg=config.loads(
                           "version: 1\nsource:\n  type: local\n  path: /tmp/other.dump\n"))
    check("refused", [f.rule for f in report.findings], ["SOURCE_AMBIGUOUS"])
    check("nothing ran", report.verified, False)


SAMPLE_CONFIG = """
version: 1
tier: sample
sample:
  tables: [customer]
volume:
  tables:
    customer: {min_rows: 1000}
"""


def test_integration_sample_tier_restores_the_rows_it_names():
    """Not a fast run wearing a different word: the sampled table's rows must
    really be there, or the volume rung would be checking nothing."""
    needs_docker()
    cfg = config.loads(SAMPLE_CONFIG)
    healthy = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
    check("healthy is clean", [f.rule for f in healthy.findings], [])
    check("volume genuinely ran", healthy.stage("volume").status, drill.OK)

    dropped = drill.run(corpus("volume_drop.dump"), cfg=cfg)
    check("and a real row loss is still caught",
          [f.rule for f in dropped.findings], ["VOLUME_BELOW_MINIMUM"])


def test_integration_sample_tier_does_not_invent_a_sequence_failure():
    """Measured: `pg_restore --data-only -t customer` restores 2000 rows and
    leaves the sequence at 1. Checking sequences here would report
    SEQUENCE_BEHIND on a perfectly good backup -- a finding about firedrill's
    own sampling rather than about the backup, which is the most damaging kind
    of false positive there is."""
    needs_docker()
    report = drill.run(corpus("healthy_pg16.dump"), cfg=config.loads(SAMPLE_CONFIG))
    check("no invented finding", "SEQUENCE_BEHIND" in
          {f.rule for f in report.findings}, False)
    check("and the report says why, accurately",
          "does not carry setval" in report.stage("integrity").detail, True)
    check("a full run does check sequences",
          "sequence(s)" in drill.run(
              corpus("healthy_pg16.dump")).stage("integrity").detail, True)


def test_config_sample_tier_refuses_checks_it_cannot_honour():
    """Each of these would produce a finding about the sampling rather than
    about the backup, so the config refuses them instead of running them."""
    _rejects("no tables", "version: 1\ntier: sample\n", "needs `sample.tables`")
    _rejects("sample set on the wrong tier",
             "version: 1\nsample:\n  tables: [a]\n", "would never be read")
    _rejects("volume rule on an unsampled table", """
version: 1
tier: sample
sample:
  tables: [customer]
volume:
  tables:
    orders: {min_rows: 1}
""", "artefact of sampling")
    _rejects("semantics", """
version: 1
tier: sample
sample:
  tables: [customer]
semantics:
  - {name: x, sql: select count(*) from t, expect: "> 0"}
""", "cannot run semantics")


def test_integration_history_becomes_the_baseline_that_catches_a_loss():
    """The point of remembering runs, as one sequence.

    Run one has nothing to compare against and says so. Run two is measured
    against it. Run three lost 99% of its rows -- within min_rows, so only the
    tolerance can catch it, and only because run one was recorded.
    """
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "history.json"
        cfg = config.loads(f"""
version: 1
history: {path}
volume:
  tolerance: 10%
  tables:
    customer: {{min_rows: 1}}
""")
        first = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
        check("clean", [f.rule for f in first.findings], [])
        check("counts recorded", first.row_counts, {"customer": 2000})
        check("nothing to compare against yet", first.trend, "")

        second = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
        check("still clean", [f.rule for f in second.findings], [])
        check("and now there is a trend", "than the last good full run" in second.trend, True)

        dropped = drill.run(corpus("volume_drop.dump"), cfg=cfg)
        check("the loss is caught by tolerance alone",
              [f.rule for f in dropped.findings], ["VOLUME_DRIFT"])
        check("naming both numbers", "20 row(s), down 99% from 2000"
              in dropped.findings[0].message, True)

        entries = json.loads(path.read_text(encoding="utf-8"))
        check("every run recorded, including the failure", len(entries), 3)
        check("the failed run is not usable as a future baseline",
              entries[-1]["ok"], False)
        blob = json.dumps(entries)
        check("and no row data reached the file", "@example.test" in blob, False)


def test_integration_growth_is_not_a_finding():
    """Tables grow. A rule that fired on growth would go off every week until
    somebody muted it, taking the real findings with it."""
    needs_docker()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "history.json"
        cfg = config.loads(f"""
version: 1
history: {path}
volume:
  tolerance: 10%
  tables:
    customer: {{min_rows: 1}}
""")
        # Record a small baseline first, then restore the full table: a 100x
        # increase, far outside the 10% tolerance, and not a problem.
        drill.run(corpus("volume_drop.dump"), cfg=cfg)
        grown = drill.run(corpus("healthy_pg16.dump"), cfg=cfg)
        check("20 -> 2000 is silent", [f.rule for f in grown.findings], [])


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
    # Resolve the fixture BEFORE breaking the environment. Building the corpus
    # needs a working daemon, and on a fresh checkout this is the first test
    # that touches it -- so sabotaging DOCKER_HOST first made this test skip
    # itself rather than run. It went green locally and would have failed CI,
    # which always starts from a clean clone.
    fixture = corpus("healthy_pg16.dump")
    import os
    saved = os.environ.get("DOCKER_HOST")
    os.environ["DOCKER_HOST"] = "unix:///firedrill-nonexistent.sock"
    try:
        report = drill.run(fixture)
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
    FLOOR = 113
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
