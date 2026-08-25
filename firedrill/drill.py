"""The Phase 0 ladder: inspect -> target -> restore -> smoke, each timed.

The single rule this module exists to enforce: a stage that could not run is
recorded as NOT RUN and the drill is not verified. There is no path through
here where skipping a stage produces a pass. `Report.verified` is False unless
a restore genuinely happened, and the exit code honours it.
"""

from __future__ import annotations

import dataclasses
import pathlib
import time

from . import archive, docker, ladder, restore as restore_stage
from .config import DEFAULT as DEFAULT_CONFIG
from .finding import DEFAULT_FAIL_ON, Finding, should_fail, worst

STAGES = ("inspect", "target", "restore", "smoke",
          "structure", "volume", "semantics", "integrity")

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
            "findings": [f.as_dict() for f in self.findings],
            "suppressed": self.suppressed,
        }


def run(dump_path: str | pathlib.Path, *, cfg=None, **kw) -> Report:
    """Drill the backup, then apply the config's suppressions.

    Suppression happens here, in one place, rather than at each of the five
    points _run can return from. A missed return would silently un-suppress a
    finding, or worse, suppress one the user never asked to hide.
    """
    cfg = cfg if cfg is not None else DEFAULT_CONFIG
    return _suppress(_run(dump_path, cfg=cfg, **kw), cfg)


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


def _run(dump_path: str | pathlib.Path, *, flavour: str = "",
         rto_budget: float | None = None, fail_on: str = DEFAULT_FAIL_ON,
         pin_major: str | None = None, cfg=DEFAULT_CONFIG,
         write_reference: str | pathlib.Path | None = None,
         ready_timeout: int = docker.DEFAULT_READY_TIMEOUT) -> Report:
    dump_path = pathlib.Path(dump_path)
    if rto_budget is None:
        rto_budget = cfg.rto_budget
    stages = [Stage(name) for name in STAGES]
    report = Report(dump=str(dump_path), stages=stages, findings=[], archive={},
                    rto_budget=rto_budget, fail_on=fail_on)
    began = time.monotonic()

    def stage(name: str) -> Stage:
        return next(s for s in stages if s.name == name)

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

    if header.format != archive.FORMAT_CUSTOM:
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
        "restored_into_major": major,
        "size_bytes": dump_path.stat().st_size,
    }
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

        stage("target").status = OK
        stage("target").seconds = time.monotonic() - started
        stage("target").detail = container.image

        # -- restore -------------------------------------------------------
        result = restore_stage.run_restore(container)
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
        if cfg.volume_tables:
            started = time.monotonic()
            found, info = ladder.volume(container, cfg, restore_stage.TARGET_DB)
            report.findings.extend(found)
            stage("volume").seconds = time.monotonic() - started
            stage("volume").status = FAILED if found else OK
            stage("volume").detail = f"{len(info.get('counts', {}))} table(s) counted"
        else:
            stage("volume").status = NOT_CONFIGURED
            stage("volume").detail = "no volume rules in the config"

        # -- semantics -----------------------------------------------------
        if cfg.semantics:
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
        found, info = ladder.integrity(container, cfg, restore_stage.TARGET_DB)
        report.findings.extend(found)
        stage("integrity").seconds = time.monotonic() - started
        stage("integrity").status = FAILED if found else OK
        stage("integrity").detail = f"{info.get('sequences', 0)} sequence(s)"
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
