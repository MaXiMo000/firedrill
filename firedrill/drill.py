"""The Phase 0 ladder: inspect -> target -> restore -> smoke, each timed.

The single rule this module exists to enforce: a stage that could not run is
recorded as NOT RUN and the drill is not verified. There is no path through
here where skipping a stage produces a pass. `Report.verified` is False unless
a restore genuinely happened, and the exit code honours it.
"""

from __future__ import annotations

import dataclasses
import pathlib
import shutil
import tempfile
import time

from . import archive, docker, history as history_module, ladder, pitr, \
    restore as restore_stage, sources
from . import config as _config_module
from .config import DEFAULT as DEFAULT_CONFIG
from .finding import DEFAULT_FAIL_ON, Finding, should_fail, worst

STAGES = ("fetch", "inspect", "target", "restore", "smoke",
          "structure", "volume", "semantics", "integrity")

# PITR has its own shape: there is no archive to inspect and no pg_restore
# to run, and the rung that matters is the boundary assertion.
PITR_STAGES = ("recover", "boundary", "integrity")

OK = "ok"
FAILED = "failed"
NOT_RUN = "not run"

# Distinct from NOT_RUN on purpose. "Nothing in the config asked for this" and
# "this was asked for and could not run" are different facts about a report,
# and collapsing either into "ok" is how a tool claims coverage it lacks.
NOT_CONFIGURED = "not configured"


@dataclasses.dataclass
class Stage:
    name: str
    status: str = NOT_RUN
    seconds: float = 0.0
    detail: str = ""


@dataclasses.dataclass
class Report:
    dump: str
    stages: list[Stage]
    findings: list[Finding]
    archive: dict
    verified: bool = False
    total_seconds: float = 0.0
    rto_budget: float | None = None
    fail_on: str = DEFAULT_FAIL_ON
    tier: str = "full"
    row_counts: dict = dataclasses.field(default_factory=dict)
    trend: str = ""
    suppressed: list = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Green requires both: it ran, and it found nothing that matters."""
        return self.verified and not should_fail(self.findings, self.fail_on)

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def stage(self, name: str) -> Stage:
        for s in self.stages:
            if s.name == name:
                return s
        raise KeyError(name)

    def as_dict(self) -> dict:
        return {
            "dump": self.dump,
            "tier": self.tier,
            "verified": self.verified,
            "ok": self.ok,
            "worst_severity": worst(self.findings),
            "total_seconds": round(self.total_seconds, 3),
            "rto_budget_seconds": self.rto_budget,
            "archive": self.archive,
            "stages": [
                {"name": s.name, "status": s.status,
                 "seconds": round(s.seconds, 3), "detail": s.detail}
                for s in self.stages
            ],
            "row_counts": self.row_counts,
            "trend": self.trend,
            "findings": [f.as_dict() for f in self.findings],
            "suppressed": self.suppressed,
        }


def run(dump_path: str | pathlib.Path | None = None, *, cfg=None, **kw) -> Report:
    """Drill the backup, then apply the config's suppressions.

    Suppression happens here, in one place, rather than at each of the five
    points _run can return from. A missed return would silently un-suppress a
    finding, or worse, suppress one the user never asked to hide.
    """
    cfg = cfg if cfg is not None else DEFAULT_CONFIG
    # One scratch directory for anything downloaded, removed however this
    # exits. A local source is read in place and never lands here, so a
    # cleanup bug cannot reach the user's own backup file.
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="firedrill-"))
    try:
        report = _suppress(_run(dump_path, cfg=cfg, workdir=workdir, **kw), cfg)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # Recorded after suppression, so the history says what the run reported
    # rather than what it would have reported with a different config. Written
    # even for a failed run: a history that only remembers the good days
    # cannot show you the day things changed.
    if cfg.history_path:
        try:
            entries = history_module.load(cfg.history_path)
            report.trend = history_module.trend(
                entries, report.total_seconds, cfg.tier)
            history_module.record(report, cfg.history_path)
        except OSError as exc:
            report.findings.append(Finding(
                stage="restore", rule="HISTORY_UNWRITABLE", severity="low",
                message=f"could not write the history file: {exc}",
                fix="The drill itself is unaffected, but no trend will be "
                    "visible until this is writable.",
                evidence="",
            ))
    return report


def run_pitr(base, wal, target: str, *, cfg=None, flavour: str = "",
             fail_on: str = DEFAULT_FAIL_ON,
             ready_timeout: int = docker.DEFAULT_READY_TIMEOUT) -> Report:
    """Recover to a timestamp, then put the result through the ladder.

    The boundary assertion -- the pre-target row is there and the post-target
    row is not -- is expressed as ordinary `semantics:` checks, so this adds a
    way of producing a database and reuses every rung that already exists.
    """
    cfg = cfg if cfg is not None else DEFAULT_CONFIG
    stages = [Stage(name) for name in PITR_STAGES]
    report = Report(dump=f"pitr {base} @ {target}", stages=stages, findings=[],
                    archive={}, fail_on=fail_on, tier=cfg.tier)
    began = time.monotonic()

    def stage(name):
        return next(s for s in stages if s.name == name)

    # Validated first, before the filesystem is touched or Docker is probed.
    # It is the cheapest check and the one that guards an injection surface;
    # doing it after reading the base meant a bad path masked a bad target.
    try:
        target = pitr.check_target(target)
    except pitr.InvalidTarget as exc:
        report.findings.append(Finding(
            stage="recover", rule="PITR_TARGET_INVALID", severity="critical",
            message=str(exc),
            fix="Pass the moment you want to recover to, as a timestamp. "
                "Nothing was started.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return _suppress(report, cfg)

    usable, why = docker.docker_available()
    if not usable:
        stage("recover").detail = why
        report.findings.append(Finding(
            stage="recover", rule="TARGET_UNAVAILABLE", severity="critical",
            message=f"the recovery could NOT be verified: {why}",
            fix="Start Docker and run again. Nothing has been proved about this "
                "base backup.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return _suppress(report, cfg)

    started = time.monotonic()
    try:
        report.archive = {"base": str(base), "wal": str(wal),
                          "recovery_target_time": target,
                          "server_major": pitr.major_of_base(base)}
    except archive.ArchiveError as exc:
        stage("recover").status = FAILED
        report.findings.append(Finding(
            stage="recover", rule="PITR_FAILED", severity="critical",
            message=f"the base backup could not be read: {exc}",
            fix="Point --base at the directory pg_basebackup produced.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return _suppress(report, cfg)

    container, found = pitr.recover(base, wal, target, flavour=flavour,
                                    ready_timeout=ready_timeout)
    stage("recover").seconds = time.monotonic() - started
    if found:
        report.findings.extend(found)
        stage("recover").status = FAILED
        stage("recover").detail = found[0].rule
        report.total_seconds = time.monotonic() - began
        return _suppress(report, cfg)

    try:
        promoted = pitr.confirm_promoted(container)
        if promoted:
            report.findings.extend(promoted)
            stage("recover").status = FAILED
            report.total_seconds = time.monotonic() - began
            return _suppress(report, cfg)

        # It came up out of recovery, so it stopped where it was told to.
        report.verified = True
        stage("recover").status = OK
        stage("recover").detail = f"recovered to {target}"
        report.archive["restored_into_major"] = _served_major(container)

        if cfg.semantics:
            started = time.monotonic()
            sem, _ = ladder.semantics(container, cfg, "postgres")
            report.findings.extend(sem)
            stage("boundary").seconds = time.monotonic() - started
            stage("boundary").status = FAILED if sem else OK
            stage("boundary").detail = f"{len(cfg.semantics)} check(s)"
        else:
            # Without the boundary checks this proves a server came up, which
            # is not what PITR is for. Not a pass.
            stage("boundary").status = NOT_CONFIGURED
            stage("boundary").detail = "no semantics checks: the boundary was not asserted"
            report.findings.append(Finding(
                stage="boundary", rule="PITR_UNASSERTED", severity="high",
                message="recovery reached the target, and nothing checked what "
                        "the database then contained",
                fix="Add two semantics checks: one row written before the target "
                    "that must exist, one written after that must not. Either "
                    "alone is satisfiable by a restore that is simply wrong.",
                evidence="",
            ))

        started = time.monotonic()
        integ, info = ladder.integrity(container, cfg, "postgres")
        report.findings.extend(integ)
        stage("integrity").seconds = time.monotonic() - started
        stage("integrity").status = FAILED if integ else OK
        stage("integrity").detail = _sequence_detail(info)
    finally:
        container.teardown()

    report.total_seconds = time.monotonic() - began
    return _suppress(report, cfg)


def _sequence_detail(info: dict) -> str:
    """`9 of 13 sequence(s)` when some could not be linked to a column.

    Partial coverage is worth seeing. pagila links 9 of its 13, and a bare
    "9 sequence(s)" reads like completeness.
    """
    checked = info.get("sequences", 0)
    present = info.get("sequences_present", checked)
    if present and present != checked:
        return f"{checked} of {present} sequence(s)"
    return f"{checked} sequence(s)"


def _served_major(container) -> str | None:
    served = container.sql("select current_setting('server_version')")
    try:
        return archive.major_of(served.stdout.strip())
    except archive.ArchiveError:
        return None


def _is_older(target: str, source: str) -> bool:
    """Is `target` an older Postgres major than `source`?

    Majors are '16', '18' -- but pre-10 releases are '9.6', so this compares
    component-wise rather than as integers. False when either is unparseable:
    a guess here would put a severity on a finding that has not been measured.
    """
    def parts(value):
        return tuple(int(n) for n in value.split("."))
    try:
        return parts(target) < parts(source)
    except (ValueError, AttributeError):
        return False


def _suppress(report: Report, cfg) -> Report:
    """Move ignored findings aside -- recorded with their reason, not deleted.

    A suppressed finding still appears in the report, under the reason its
    author wrote (PLAN.md §6). Deleting it outright would make the config a
    way to make problems invisible, which is the opposite of the point.
    """
    kept = []
    for finding in report.findings:
        if cfg.is_ignored(finding.rule):
            report.suppressed.append({
                "rule": finding.rule,
                "severity": finding.severity,
                "reason": cfg.reason_for(finding.rule),
                "message": finding.message,
            })
        else:
            kept.append(finding)
    report.findings = kept
    return report


def _run(dump_path: str | pathlib.Path | None = None, *, flavour: str = "",
         rto_budget: float | None = None, fail_on: str = DEFAULT_FAIL_ON,
         pin_major: str | None = None, cfg=DEFAULT_CONFIG,
         write_reference: str | pathlib.Path | None = None,
         workdir: pathlib.Path | None = None,
         ready_timeout: int = docker.DEFAULT_READY_TIMEOUT) -> Report:
    if rto_budget is None:
        rto_budget = cfg.rto_budget
    stages = [Stage(name) for name in STAGES]
    report = Report(dump=str(dump_path or ""), stages=stages, findings=[], archive={},
                    rto_budget=rto_budget, fail_on=fail_on, tier=cfg.tier)
    began = time.monotonic()

    def stage(name: str) -> Stage:
        return next(s for s in stages if s.name == name)

    # The baseline this run is measured against, read before anything is
    # restored so a failed run cannot become its own reference.
    entries = history_module.load(cfg.history_path) if cfg.history_path else []
    baseline = history_module.last_good(entries, cfg.tier)

    # -- fetch -------------------------------------------------------------
    # A positional path and a configured source both name one artefact; local
    # is the degenerate case, so there is one code path and the checksum check
    # applies to a local file too.
    source = cfg.source
    if source is None:
        source = _config_module.Source(type="local", path=str(dump_path))
    elif dump_path is not None:
        report.findings.append(Finding(
            stage="fetch", rule="SOURCE_AMBIGUOUS", severity="critical",
            message="a dump path was given on the command line and the config "
                    "also defines a source",
            fix="Remove one. Guessing which backup was meant is the one thing a "
                "restore tool must never do.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return report

    try:
        artifact = sources.fetch(source, workdir or pathlib.Path("."))
    except sources.SourceError as exc:
        stage("fetch").status = NOT_RUN
        stage("fetch").detail = str(exc).splitlines()[0]
        report.findings.append(Finding(
            stage="fetch", rule="FETCH_FAILED", severity="critical",
            message=f"the backup could NOT be verified: {exc}",
            fix="Nothing was restored, so nothing has been proved about this "
                "backup. A backup that cannot be fetched is not a backup.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return report

    dump_path = artifact.path
    report.dump = artifact.origin
    stage("fetch").status = OK
    stage("fetch").seconds = artifact.fetch_seconds
    checked = ("sha256 verified" if source.sha256
               else "size verified" if source.size is not None
               else "unverified")
    stage("fetch").detail = f"{artifact.size:,} bytes from {source.type}  {checked}"

    # A remote artefact nobody checked is a restore of whatever was at the far
    # end, not of the backup the job wrote. For `local` the operator handed us
    # a specific file and a digest of it proves nothing they do not already
    # know; for `https` and `s3` the bytes travelled, and for s3 firedrill even
    # chose the object -- `_newest_key` takes whatever is newest under the
    # prefix, so a partial upload, a second producer writing to the same place,
    # or last night's job never landing all look identical from here.
    #
    # Medium: below the default fail-on, because plenty of deployments cannot
    # produce a digest at backup time and this must not break their build. It
    # is reported rather than left silent for the same reason SEQUENCE_UNCHECKED
    # is -- the stage said `ok`, and `ok` was being read as `verified`.
    if source.type in ("https", "s3") and source.sha256 is None and source.size is None:
        report.findings.append(Finding(
            stage="fetch", rule="ARTEFACT_UNVERIFIED", severity="medium",
            message="the artefact was fetched but nothing checked it was the "
                    "backup that was written",
            fix="Set `source.sha256` to the digest your backup job recorded, or "
                "`source.size` if a digest is not available. Without either, a "
                "green run says these bytes restore -- not that they are the "
                "bytes you meant to restore.",
            evidence=f"{artifact.origin}",
        ))

    # -- inspect -----------------------------------------------------------
    started = time.monotonic()
    try:
        header = archive.read_header(dump_path)
    except archive.ArchiveError as exc:
        stage("inspect").status = FAILED
        stage("inspect").seconds = time.monotonic() - started
        stage("inspect").detail = str(exc)
        report.findings.append(Finding(
            stage="inspect", rule="ARCHIVE_UNREADABLE", severity="critical",
            message=f"could not read the archive header: {exc}",
            fix="The file is not a readable pg_dump custom-format archive. If the "
                "backup job reported success, it is lying: check for a truncated "
                "write, a wrong path, or an encrypted/compressed wrapper.",
            evidence=str(dump_path),
        ))
        report.total_seconds = time.monotonic() - began
        return report

    # custom (-Fc), directory (-Fd) and tar (-Ft) all carry a PGDMP header and
    # are all restorable by pg_restore. Plain SQL is not: it has no header, so
    # the major version cannot be read out of it, and version-matching is the
    # thing this tool is built on.
    if header.format not in archive.RESTORABLE_FORMATS:
        stage("inspect").status = FAILED
        stage("inspect").seconds = time.monotonic() - started
        report.findings.append(Finding(
            stage="inspect", rule="FORMAT_UNSUPPORTED", severity="critical",
            message=f"archive is {header.format_name} format; Phase 0 handles "
                    f"custom (-Fc) only",
            fix="Re-dump with `pg_dump -Fc`, or wait for the phase that adds the "
                "other formats. Reported rather than skipped so this can never "
                "look like a pass.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return report

    major = pin_major or header.server_major
    report.archive = {
        "archive_version": ".".join(str(n) for n in header.archive_version),
        "format": header.format_name,
        "source_dbname": header.dbname,
        "server_version": header.server_version,
        "server_major": header.server_major,
        # What we will ask for. Overwritten below with what the server
        # actually reports, once there is a server to ask.
        "target_major_requested": major,
        "restored_into_major": None,
        "size_bytes": dump_path.stat().st_size,
    }
    # A pinned major that disagrees with the archive is knowable here, before
    # a container is started, and it explains a failure that otherwise arrives
    # as a generic "could not execute query" several stages later.
    if pin_major and pin_major != header.server_major:
        older = _is_older(pin_major, header.server_major)
        report.findings.append(Finding(
            stage="inspect", rule="VERSION_MISMATCH",
            severity="high" if older else "medium",
            message=f"the archive is from PostgreSQL {header.server_major} and "
                    f"--postgres pinned {pin_major}",
            fix=("A dump cannot restore into an older major version; this will "
                 "fail. Drop the pin and let the version be read from the "
                 "archive." if older else
                 "Restoring into a newer major usually works, but it is not the "
                 "version this backup came from, so it is not the version your "
                 "recovery would use. Drop the pin to match the archive."),
            evidence="",
        ))

    stage("inspect").status = OK
    stage("inspect").seconds = time.monotonic() - started
    stage("inspect").detail = f"{header.server_version} ({header.format_name})"

    # -- target ------------------------------------------------------------
    usable, why = docker.docker_available()
    if not usable:
        stage("target").status = NOT_RUN
        stage("target").detail = why
        report.findings.append(Finding(
            stage="target", rule="TARGET_UNAVAILABLE", severity="critical",
            message=f"the restore could NOT be verified: {why}",
            fix="Start Docker and run again. This is deliberately not a pass: a "
                "verification that could not run has proved nothing.",
            evidence="",
        ))
        report.total_seconds = time.monotonic() - began
        return report

    container = docker.Container(major, dump=dump_path, flavour=flavour,
                                 ready_timeout=ready_timeout)
    started = time.monotonic()
    try:
        try:
            container.start()
            container.wait_ready()
        except docker.TargetError as exc:
            stage("target").status = FAILED
            stage("target").seconds = time.monotonic() - started
            stage("target").detail = str(exc).splitlines()[0]
            report.findings.append(Finding(
                stage="target", rule="TARGET_UNAVAILABLE", severity="critical",
                # Same contract wording as the daemon-missing path above. Which
                # of the two fired is an implementation detail; "could NOT be
                # verified" is the promise the report makes either way, and a
                # test that only held for one path let a real CI failure through.
                message=f"the restore could NOT be verified: postgres:{major} "
                        f"did not come up: {exc}",
                fix="Without a target the restore did not happen, so nothing about "
                    "this backup has been proved.",
                evidence=str(exc),
            ))
            report.total_seconds = time.monotonic() - began
            return report

        # Ask the server what it is, rather than reporting what we asked for.
        # These agree because the image tag decides it -- but "the version we
        # intended" and "the version that restored the dump" are different
        # claims, and only one of them is a measurement.
        served = container.sql("select current_setting('server_version')")
        try:
            report.archive["restored_into_major"] = archive.major_of(
                served.stdout.strip())
        except archive.ArchiveError:
            report.archive["restored_into_major"] = None

        stage("target").status = OK
        stage("target").seconds = time.monotonic() - started
        stage("target").detail = container.image

        # -- restore -------------------------------------------------------
        result = restore_stage.run_restore(container, tier=cfg.tier,
                                           tables=cfg.sample_tables)
        report.findings.extend(result.findings)
        stage("restore").seconds = result.seconds
        stage("restore").status = OK if result.exit_code == 0 else FAILED
        stage("restore").detail = (
            f"exit {result.exit_code}"
            + (f", {result.errors_ignored} error(s) ignored" if result.errors_ignored else "")
        )
        # The restore ran and was observed. That -- not its outcome -- is what
        # makes the run verified.
        report.verified = True

        # -- smoke ---------------------------------------------------------
        started = time.monotonic()
        smoke_findings, info = restore_stage.smoke(container)
        report.findings.extend(smoke_findings)
        stage("smoke").seconds = time.monotonic() - started
        stage("smoke").status = FAILED if smoke_findings else OK
        if info:
            stage("smoke").detail = f"{info.get('tables')} user table(s)"

        # -- structure -----------------------------------------------------
        # --write-reference writes the snapshot instead of comparing against
        # one. Doing both would let a run regenerate the reference it is being
        # judged against, which is a check that can never fail.
        if write_reference is not None:
            started = time.monotonic()
            try:
                pathlib.Path(write_reference).write_text(
                    ladder.snapshot(container, restore_stage.TARGET_DB),
                    encoding="utf-8")
                stage("structure").status = OK
                stage("structure").detail = f"wrote {write_reference}"
            except (RuntimeError, OSError) as exc:
                stage("structure").status = FAILED
                stage("structure").detail = str(exc)
                report.findings.append(Finding(
                    stage="structure", rule="STRUCTURE_UNREADABLE", severity="high",
                    message="could not write the structure reference",
                    fix="The snapshot was not written, so nothing was recorded.",
                    evidence=str(exc),
                ))
            stage("structure").seconds = time.monotonic() - started
        elif cfg.structure_reference is not None:
            started = time.monotonic()
            found, info = ladder.structure(container, cfg, restore_stage.TARGET_DB)
            report.findings.extend(found)
            stage("structure").seconds = time.monotonic() - started
            stage("structure").status = FAILED if found else OK
            stage("structure").detail = f"{info.get('objects', 0)} object(s) compared"
        else:
            stage("structure").status = NOT_CONFIGURED
            stage("structure").detail = "no structure.reference in the config"

        # -- volume --------------------------------------------------------
        # Only the rungs the config actually asked for run. The ones it did
        # not ask for say "not configured", which is the honest thing for a
        # report to say and is not the same as a tick.
        if cfg.tier == "fast":
            # PLAN.md §3.5. A schema-only restore contains no rows, so every
            # table would count zero and every minimum would "fail" -- or, with
            # no rules configured, the rung would show a tick for a question it
            # never asked. Neither is honest, so it did not run.
            stage("volume").status = NOT_RUN
            stage("volume").detail = "fast tier restored no rows"
        elif cfg.volume_tables:
            started = time.monotonic()
            found, info = ladder.volume(
                container, cfg, restore_stage.TARGET_DB,
                baseline=(baseline or {}).get("row_counts"))
            report.findings.extend(found)
            report.row_counts = info.get("counts", {})
            stage("volume").seconds = time.monotonic() - started
            stage("volume").status = FAILED if found else OK
            stage("volume").detail = f"{len(info.get('counts', {}))} table(s) counted"
        else:
            stage("volume").status = NOT_CONFIGURED
            stage("volume").detail = "no volume rules in the config"

        # -- semantics -----------------------------------------------------
        if cfg.tier in ("fast", "sample"):
            # sample cannot run these either: a smoke query is arbitrary SQL,
            # so there is no telling whether it reads a table whose rows were
            # restored. config.py refuses the combination outright; this is the
            # belt to that pair of braces.
            stage("semantics").status = NOT_RUN
            stage("semantics").detail = f"{cfg.tier} tier: not all rows restored"
        elif cfg.semantics:
            started = time.monotonic()
            found, info = ladder.semantics(container, cfg, restore_stage.TARGET_DB)
            report.findings.extend(found)
            stage("semantics").seconds = time.monotonic() - started
            stage("semantics").status = FAILED if found else OK
            stage("semantics").detail = f"{len(cfg.semantics)} check(s)"
        else:
            stage("semantics").status = NOT_CONFIGURED
            stage("semantics").detail = "no semantics checks in the config"

        # -- integrity -----------------------------------------------------
        # This one needs no configuration: the questions it asks are the same
        # for every database, so it always runs.
        started = time.monotonic()
        # Measured: `pg_restore --data-only -t customer` restores the rows and
        # leaves the sequence at 1, so a sample run would report SEQUENCE_BEHIND
        # on a perfectly good backup. That finding would be about firedrill's
        # sampling, not about the backup, which makes it a false positive of the
        # most damaging kind -- so sequences are not checked in either tier.
        found, info = ladder.integrity(container, cfg, restore_stage.TARGET_DB,
                                       sequences=cfg.tier == "full")
        report.findings.extend(found)
        stage("integrity").seconds = time.monotonic() - started
        stage("integrity").status = FAILED if found else OK
        # Collation is a catalog fact and survives either partial restore. The
        # reason sequences are skipped differs by tier, and saying "needs rows"
        # for a sample run would be wrong: the rows are there, the setval is
        # not, because it is not part of a -t data restore.
        stage("integrity").detail = (
            _sequence_detail(info) if cfg.tier == "full"
            else "collation only -- fast tier restored no rows"
            if cfg.tier == "fast"
            else "collation only -- a sampled restore does not carry setval")
    finally:
        # PLAN.md §7: teardown in a finally, always.
        container.teardown()

    report.total_seconds = time.monotonic() - began

    if rto_budget is not None and report.total_seconds > rto_budget:
        report.findings.append(Finding(
            stage="restore", rule="RTO_EXCEEDED", severity="medium",
            message=f"the drill took {report.total_seconds:.1f}s against a stated "
                    f"budget of {rto_budget:.0f}s",
            fix="Either the budget is wrong or the restore is getting slower. "
                "Both are worth knowing before an outage rather than during one.",
            evidence="",
        ))
    return report
