"""One webhook POST with the verdict.

The payload carries `text` (what Slack and Mattermost read) and `content`
(what Discord reads) with the same one-line summary, plus the structured
fields for anything else. The URL comes from an environment variable named
on the command line: a webhook URL is a credential, and argv is not a place
for one.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .finding import worst


class NotifyError(Exception):
    pass


def summary(report) -> str:
    if not report.verified:
        head = "COULD NOT VERIFY"
    elif report.ok:
        head = "PASS"
    else:
        head = "FAIL"
    line = f"firedrill {head}: {report.dump}"
    if report.findings:
        top = sorted(report.findings, key=lambda f: ("critical", "high", "medium", "low", "info")
                     .index(f.severity))[0]
        line += f" -- {len(report.findings)} finding(s), worst {top.rule}: {top.message}"
    return line[:1900]  # Discord's content limit is 2000


def payload(report) -> dict:
    text = summary(report)
    return {"text": text, "content": text, "ok": report.ok, "verified": report.verified,
            "worst": worst(report.findings), "findings": [f.rule for f in report.findings],
            "seconds": round(report.total_seconds, 2)}


def send(report, env_var: str, when: str = "fail", opener=urllib.request.urlopen) -> bool:
    """True if a notification went out. `when="fail"` also covers COULD NOT
    VERIFY -- a drill that did not happen is exactly what someone must hear."""
    if when == "fail" and report.ok:
        return False
    url = os.environ.get(env_var)
    if not url:
        raise NotifyError(f"${env_var} is not set")
    if not url.startswith("https://") and not url.startswith(("http://localhost", "http://127.0.0.1")):
        raise NotifyError(f"${env_var} must be an https:// URL")
    request = urllib.request.Request(url, data=json.dumps(payload(report)).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener(request, timeout=30) as response:
            response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # The URL itself is never in the message.
        raise NotifyError(f"the webhook in ${env_var} did not accept it: "
                          f"{getattr(exc, 'code', '') or type(exc).__name__}") from None
    return True
