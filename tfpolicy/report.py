"""Turn a Result into text for people (terminal, Markdown for PR comments) or JSON for tools."""

from __future__ import annotations

import json

from tfpolicy.engine import Result


def as_text(result: Result) -> str:
    lines = [f"Checked {result.resources_checked} resource(s) with {len(result.rules_run)} rule(s)."]
    for v in result.violations:
        tag = "EXEMPT" if v.exempted_by else v.severity.upper()
        lines.append(f"  [{tag:7}] {v.rule:20} {v.address}: {v.message}")
        if v.exempted_by:
            lines.append(f"            exemption: {v.exempted_by}")
    for note in result.notes:
        lines.append(f"  [NOTE   ] {note}")
    errors = sum(1 for v in result.active if v.severity == "error")
    warnings = sum(1 for v in result.active if v.severity == "warning")
    exempt = sum(1 for v in result.violations if v.exempted_by)
    verdict = "FAIL" if result.failed else "PASS"
    lines.append(f"{verdict}: {errors} error(s), {warnings} warning(s), {exempt} exempted (fail on: {result.fail_on})")
    return "\n".join(lines)


def as_markdown(result: Result) -> str:
    icon = "❌" if result.failed else "✅"
    lines = [f"### {icon} Terraform policy check: {'FAILED' if result.failed else 'passed'}", ""]
    if result.violations:
        lines += ["| | Rule | Resource | Problem |", "|---|---|---|---|"]
        for v in result.violations:
            mark = "🟡 exempt" if v.exempted_by else ("🔴 error" if v.severity == "error" else "🟠 warning")
            detail = f"{v.message}<br>_exemption: {v.exempted_by}_" if v.exempted_by else v.message
            lines.append(f"| {mark} | `{v.rule}` | `{v.address}` | {detail} |")
    else:
        lines.append("No violations.")
    if result.notes:
        lines += ["", "**Notes**", ""] + [f"- {note}" for note in result.notes]
    lines += ["", f"_{result.resources_checked} resources, rules: {', '.join(result.rules_run)}_"]
    return "\n".join(lines)


def as_json(result: Result) -> str:
    return json.dumps(
        {
            "passed": not result.failed,
            "fail_on": result.fail_on,
            "resources_checked": result.resources_checked,
            "rules_run": result.rules_run,
            "violations": [v.__dict__ for v in result.violations],
            "notes": result.notes,
        },
        indent=2,
    )


def github_annotations(result: Result) -> str:
    """Lines GitHub Actions turns into error/warning annotations on the run page."""
    lines = []
    for v in result.active:
        level = "error" if v.severity == "error" else "warning"
        lines.append(f"::{level} title=Policy {v.rule}::{v.address}: {v.message}")
    return "\n".join(lines)


FORMATS = {"text": as_text, "markdown": as_markdown, "json": as_json}
