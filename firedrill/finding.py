"""The one Finding model, and the redaction that keeps data out of it.

Two structural rules, both enforced here rather than by reviewer discipline:

1. The field set is fixed and asserted by a test. There is deliberately no
   field capable of holding a row, a result set or a credential -- so the
   reporters have nothing dangerous to print even if someone wants them to.
2. Everything that goes into `message` or `evidence` passes through `redact`,
   which strips connection-string secrets and any password this process
   generated. A DR tool runs against real customer data; its output is the
   one place that data must never reach.
"""

from __future__ import annotations

import dataclasses
import re

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Severities at or above this fail the run by default.
DEFAULT_FAIL_ON = "high"

# Passwords minted by this process (the ephemeral container's). Registered at
# creation so redact() can scrub them out of any subprocess output we capture,
# including output we did not anticipate.
_SESSION_SECRETS: set[str] = set()

_URI_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z][\w+.-]*://)[^/\s:@]+:[^/\s@]+@")
_KEYWORD_SECRET = re.compile(
    r"(?i)\b(password|pgpassword|passwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)(\S+)"
)

# Evidence is a diagnostic, not a transcript. pg_restore can echo a failing
# statement, and a failing COPY statement can carry row values with it.
MAX_EVIDENCE = 2000


def register_secret(value: str) -> None:
    """Mark a literal string as never printable."""
    if value and len(value) >= 6:
        _SESSION_SECRETS.add(value)


def forget_secrets() -> None:
    _SESSION_SECRETS.clear()


def redact(text: str) -> str:
    """Remove credentials from text bound for a report.

    Order matters: session secrets first, because a generated password can
    legitimately look like ordinary text and would otherwise survive the
    pattern-based passes.
    """
    if not text:
        return text
    for secret in _SESSION_SECRETS:
        text = text.replace(secret, "[redacted]")
    text = _URI_CREDENTIALS.sub(r"\g<scheme>[redacted]@", text)
    text = _KEYWORD_SECRET.sub(r"\1\2[redacted]", text)
    return text


@dataclasses.dataclass(frozen=True)
class Finding:
    stage: str
    rule: str
    severity: str
    message: str
    fix: str = ""
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        # frozen=True, so assignment goes through object.__setattr__.
        object.__setattr__(self, "message", redact(self.message))
        object.__setattr__(self, "fix", redact(self.fix))
        evidence = redact(self.evidence)
        if len(evidence) > MAX_EVIDENCE:
            evidence = evidence[:MAX_EVIDENCE] + "\n... [truncated]"
        object.__setattr__(self, "evidence", evidence)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def worst(findings) -> str | None:
    """The highest severity present, or None."""
    for severity in SEVERITIES:
        if any(f.severity == severity for f in findings):
            return severity
    return None


def should_fail(findings, fail_on: str = DEFAULT_FAIL_ON) -> bool:
    threshold = SEVERITIES.index(fail_on)
    return any(SEVERITIES.index(f.severity) <= threshold for f in findings)
