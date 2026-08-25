"""firedrill.yml -> typed settings, refusing ambiguity.

This module says "no" a lot, on purpose. Every rejection here is a failure
mode that would otherwise be silent:

* An unknown key is an error, not a warning. A typo'd `tolerence:` that the
  loader ignores means a check the user believes is running is not running,
  and the run goes green. That is the exact shape of failure this whole
  project exists to catch, so it is not tolerated in our own config.
* A key for a phase that is not built yet is an error naming the phase. A
  parsed-and-ignored setting is a silent skip wearing a config file's clothes.
* An `ignore:` entry with no written reason is an error (PLAN.md §6). An
  unexplained suppression is how a green run stops meaning anything.
* A `semantics.expect` must be a comparison against a number. The config
  schema structurally cannot express "print this query's result", which is
  how PLAN.md §7's "smoke queries return shapes, never rows" is enforced by
  the parser rather than by reviewer discipline.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - import-time guard
    raise ModuleNotFoundError(
        "firedrill needs PyYAML to read a config file. `pip install firedrill` "
        "installs it; `pip install pyyaml` fixes a broken environment."
    ) from exc


class ConfigError(Exception):
    """A config that cannot be honoured exactly as written."""


_NO_TOLERANCE_YET = (
    "{where} is not implemented yet. A tolerance is measured against the last "
    "known-good restore, and nothing records one until history.json arrives "
    "(PLAN.md §9 Phase 3). Refused rather than accepted-and-ignored: a key "
    "that parses and is never read is the silent skip this loader exists to "
    "prevent. Use min_rows for an absolute floor in the meantime."
)

# The only tier implemented. fast/sample are PLAN.md §9 Phase 2; accepting
# either now would run a full restore and report the tier the user asked for,
# which is a lie about what was verified.
IMPLEMENTED_TIERS = ("full", "fast")
ALL_TIERS = ("fast", "sample", "full")

_EXPECT = re.compile(r"^\s*(==|!=|>=|<=|>|<)\s*(-?\d+)\s*$")
_PERCENT = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*%\s*$")

# A table name is interpolated into a count query, so it is constrained to a
# plain (optionally schema-qualified) identifier here rather than escaped
# later. Refusing the exotic-but-legal cases costs a user with a table called
# "my table" one rename; accepting them costs a quoting bug in a tool that
# runs SQL against a database.
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$")

_OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
}


def parse_duration(text: str | int | float) -> float:
    """'45m', '90s', '2h', or bare seconds."""
    if isinstance(text, (int, float)):
        return float(text)
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    try:
        if text and text[-1] in units:
            return float(text[:-1]) * units[text[-1]]
        return float(text)
    except ValueError:
        raise ConfigError(
            f"could not read {text!r} as a duration; use 45m, 90s, 2h or a "
            "number of seconds"
        ) from None


def parse_percent(text: str) -> float:
    """'10%' -> 0.10. The % is required, because bare 10 is ambiguous."""
    match = _PERCENT.match(str(text))
    if not match:
        raise ConfigError(
            f"tolerance {text!r} must be written as a percentage, e.g. '10%'. "
            "A bare number is ambiguous -- 10 could mean 10% or 10 rows, and "
            "guessing wrong silently changes what passes."
        )
    return float(match.group(1)) / 100.0


def _require_mapping(value, where: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(mapping: dict, known: tuple[str, ...], where: str) -> None:
    unknown = [k for k in mapping if k not in known]
    if unknown:
        raise ConfigError(
            f"unknown key(s) in {where}: {', '.join(sorted(map(str, unknown)))}. "
            f"Known keys: {', '.join(known)}. This is an error rather than a "
            "warning because an ignored key means a check you think is running "
            "is not."
        )


@dataclasses.dataclass(frozen=True)
class SemanticCheck:
    """A user smoke query and the shape its single value must have."""
    name: str
    sql: str
    op: str
    threshold: int

    def holds(self, value: int) -> bool:
        return _OPS[self.op](value, self.threshold)

    @property
    def expectation(self) -> str:
        return f"{self.op} {self.threshold}"


@dataclasses.dataclass(frozen=True)
class VolumeRule:
    min_rows: int | None = None
    tolerance: float | None = None


@dataclasses.dataclass(frozen=True)
class Config:
    version: int = 1
    tier: str = "full"
    rto_budget: float | None = None
    structure_reference: pathlib.Path | None = None
    volume_tolerance: float | None = None
    volume_tables: dict = dataclasses.field(default_factory=dict)
    semantics: tuple = ()
    ignore: dict = dataclasses.field(default_factory=dict)
    path: pathlib.Path | None = None

    def is_ignored(self, rule: str) -> bool:
        return rule in self.ignore

    def reason_for(self, rule: str) -> str:
        return self.ignore.get(rule, "")


DEFAULT = Config()

_TOP = ("version", "target", "tier", "rto_budget", "structure", "volume",
        "semantics", "ignore")


def loads(text: str, path: pathlib.Path | None = None) -> Config:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse the config file: {exc}") from None

    if raw is None:
        raise ConfigError(
            "the config file is empty. Delete it to use defaults, rather than "
            "leaving a file that looks like it configures something."
        )
    raw = _require_mapping(raw, "the config file")
    _reject_unknown(raw, _TOP, "the config file")

    version = raw.get("version")
    if version != 1:
        raise ConfigError(
            f"config version {version!r} is not supported; this build reads "
            "version 1. Set `version: 1` explicitly so an old file cannot be "
            "read under new rules."
        )

    # -- target ------------------------------------------------------------
    target = _require_mapping(raw.get("target"), "target")
    _reject_unknown(target, ("type", "postgres"), "target")
    target_type = target.get("type", "docker")
    if target_type != "docker":
        raise ConfigError(
            f"target.type {target_type!r} is not available. Only `docker` "
            "exists: the safest implementation of PLAN.md §7's 'refuses any "
            "target it did not create' is to have no other target. The dsn "
            "target arrives with its four interlocks."
        )

    # -- tier --------------------------------------------------------------
    tier = raw.get("tier", "full")
    if tier not in ALL_TIERS:
        raise ConfigError(f"tier {tier!r} must be one of {', '.join(ALL_TIERS)}")
    if tier not in IMPLEMENTED_TIERS:
        raise ConfigError(
            f"tier {tier!r} is not implemented yet (PLAN.md §9 Phase 2). "
            "Refused rather than silently upgraded to `full`, because a report "
            "saying 'fast' when a full restore ran is a lie about what was "
            "verified -- and so is the reverse."
        )

    rto = raw.get("rto_budget")
    rto_budget = parse_duration(rto) if rto is not None else None

    # -- structure ---------------------------------------------------------
    structure = _require_mapping(raw.get("structure"), "structure")
    _reject_unknown(structure, ("reference",), "structure")
    reference = structure.get("reference")
    structure_reference = pathlib.Path(reference) if reference else None

    # -- volume ------------------------------------------------------------
    volume = _require_mapping(raw.get("volume"), "volume")
    _reject_unknown(volume, ("tolerance", "tables"), "volume")
    # A tolerance is a comparison against the last known-good restore, and
    # nothing records one until history.json arrives in Phase 3. Parsing it and
    # then never reading it would be precisely the silently-ignored key that
    # _reject_unknown exists to prevent -- the rule has to bind its author too.
    if "tolerance" in volume:
        raise ConfigError(_NO_TOLERANCE_YET.format(where="volume.tolerance"))
    volume_tolerance = None

    volume_tables: dict[str, VolumeRule] = {}
    for name, spec in _require_mapping(volume.get("tables"), "volume.tables").items():
        spec = _require_mapping(spec, f"volume.tables.{name}")
        _reject_unknown(spec, ("min_rows", "tolerance"), f"volume.tables.{name}")
        if not _IDENT.match(str(name)):
            raise ConfigError(
                f"volume.tables.{name!r} is not a plain table name. Use `orders` "
                "or `public.orders`; the name goes into a count query, so it is "
                "restricted here rather than escaped later."
            )
        if not spec:
            raise ConfigError(
                f"volume.tables.{name} sets nothing. Give it min_rows or a "
                "tolerance, or remove it -- an empty rule checks nothing while "
                "looking like it checks something."
            )
        min_rows = spec.get("min_rows")
        if min_rows is not None and (not isinstance(min_rows, int) or min_rows < 0):
            raise ConfigError(
                f"volume.tables.{name}.min_rows must be a non-negative integer"
            )
        if "tolerance" in spec:
            raise ConfigError(
                _NO_TOLERANCE_YET.format(where=f"volume.tables.{name}.tolerance"))
        volume_tables[str(name)] = VolumeRule(min_rows=min_rows)

    # -- semantics ---------------------------------------------------------
    semantics = _parse_semantics(raw.get("semantics"))

    # -- ignore ------------------------------------------------------------
    ignore = _parse_ignore(raw.get("ignore"))

    return Config(
        version=1,
        tier=tier,
        rto_budget=rto_budget,
        structure_reference=structure_reference,
        volume_tolerance=volume_tolerance,
        volume_tables=volume_tables,
        semantics=tuple(semantics),
        ignore=ignore,
        path=path,
    )


def _parse_semantics(raw) -> list[SemanticCheck]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("semantics must be a list of checks")

    checks: list[SemanticCheck] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        where = f"semantics[{index}]"
        entry = _require_mapping(entry, where)
        _reject_unknown(entry, ("name", "sql", "expect"), where)

        name = str(entry.get("name") or "").strip()
        if not name:
            raise ConfigError(f"{where} needs a name; it is what the report prints")
        if name in seen:
            raise ConfigError(
                f"two semantics checks are both named {name!r}. Names identify "
                "findings, so duplicates make a report ambiguous."
            )
        seen.add(name)

        sql = str(entry.get("sql") or "").strip().rstrip(";").strip()
        if not sql:
            raise ConfigError(f"{where} ({name}) needs a sql query")
        if ";" in sql:
            raise ConfigError(
                f"{where} ({name}) contains more than one statement. A check is "
                "a single query returning a single number."
            )

        expect = entry.get("expect")
        if expect is None:
            raise ConfigError(
                f"{where} ({name}) needs an `expect` such as '> 0' or '== 0'."
            )
        match = _EXPECT.match(str(expect))
        if not match:
            raise ConfigError(
                f"{where} ({name}) has expect {expect!r}, which is not a "
                "comparison against a number. Write '> 0', '== 0', '>= 100'. "
                "Only comparisons are expressible, because PLAN.md §7 forbids a "
                "check whose result is echoed verbatim -- the query returns a "
                "count and the config compares it, so no row value can reach a "
                "report."
            )
        checks.append(SemanticCheck(
            name=name, sql=sql, op=match.group(1), threshold=int(match.group(2))
        ))
    return checks


def _parse_ignore(raw) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise ConfigError("ignore must be a list of {check, reason} entries")

    ignore: dict[str, str] = {}
    for index, entry in enumerate(raw):
        where = f"ignore[{index}]"
        entry = _require_mapping(entry, where)
        _reject_unknown(entry, ("check", "reason"), where)
        check = str(entry.get("check") or "").strip()
        if not check:
            raise ConfigError(f"{where} needs a `check`, the rule id to suppress")
        reason = str(entry.get("reason") or "").strip()
        if not reason:
            raise ConfigError(
                f"{where} suppresses {check} with no written reason. PLAN.md §6: "
                "every ignore requires one, and an unexplained suppression is a "
                "config error rather than a warning. It is the one piece of "
                "process this tool imposes, and it is what keeps a green run "
                "meaning something."
            )
        ignore[check] = reason
    return ignore


def load(path: str | pathlib.Path) -> Config:
    path = pathlib.Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read {path}: {exc}") from None
    return loads(text, path=path)


def find(start: str | pathlib.Path = ".") -> pathlib.Path | None:
    """firedrill.yml beside the invocation, if there is one."""
    for name in ("firedrill.yml", "firedrill.yaml"):
        candidate = pathlib.Path(start) / name
        if candidate.exists():
            return candidate
    return None
