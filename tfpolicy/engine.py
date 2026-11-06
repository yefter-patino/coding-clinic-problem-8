"""Load the policy file, run the rules, apply exemptions, decide pass or fail."""

from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tfpolicy.rules import RULES

SEVERITIES = ("error", "warning")


class PolicyError(ValueError):
    pass


@dataclass
class Violation:
    rule: str
    severity: str
    address: str
    message: str
    exempted_by: str = ""  # the exemption's reason, when one applies


@dataclass
class Result:
    violations: list[Violation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    resources_checked: int = 0
    fail_on: str = "error"

    @property
    def active(self) -> list[Violation]:
        return [v for v in self.violations if not v.exempted_by]

    @property
    def failed(self) -> bool:
        levels = ("error",) if self.fail_on == "error" else SEVERITIES
        return any(v.severity in levels for v in self.active)


def load_policy(path: str | Path) -> dict:
    try:
        policy = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as err:
        raise PolicyError(f"cannot read the policy file {path}: {err}") from err

    if policy.get("version") != 1:
        raise PolicyError(f"{path}: 'version: 1' is required")
    if policy.get("fail_on", "error") not in SEVERITIES:
        raise PolicyError(f"{path}: fail_on must be error or warning")
    rules = policy.get("rules") or {}
    if not isinstance(rules, dict) or not rules:
        raise PolicyError(f"{path}: 'rules' must list at least one rule")
    for name, settings in rules.items():
        if name not in RULES:
            raise PolicyError(f"{path}: unknown rule '{name}'. Known rules: {', '.join(sorted(RULES))}")
        if (settings or {}).get("severity", "error") not in SEVERITIES:
            raise PolicyError(f"{path}: rule {name}: severity must be error or warning")
    for number, exemption in enumerate(policy.get("exemptions") or [], start=1):
        missing = [key for key in ("rule", "address", "reason", "expires") if not exemption.get(key)]
        if missing:
            raise PolicyError(f"{path}: exemption {number} is missing {missing} (every exemption needs a reason and an end date)")
        try:
            dt.date.fromisoformat(str(exemption["expires"]))
        except ValueError as err:
            raise PolicyError(f"{path}: exemption {number}: expires must be YYYY-MM-DD") from err
    return policy


def _matching_exemption(violation: Violation, exemptions: list[dict], today: dt.date, used: set, notes: list):
    for index, exemption in enumerate(exemptions):
        if exemption["rule"] not in (violation.rule, "*"):
            continue
        if not fnmatch.fnmatch(violation.address, str(exemption["address"])):
            continue
        if dt.date.fromisoformat(str(exemption["expires"])) < today:
            notes.append(f"exemption for {exemption['address']} ({exemption['rule']}) EXPIRED on {exemption['expires']}")
            continue
        used.add(index)
        return exemption
    return None


def evaluate(resources, policy: dict, infracost: dict | None = None, today: dt.date | None = None) -> Result:
    today = today or dt.date.today()
    result = Result(fail_on=policy.get("fail_on", "error"), resources_checked=len(resources))
    context = {"infracost": infracost, "notes": result.notes}
    exemptions = policy.get("exemptions") or []
    used: set[int] = set()

    for name, settings in policy["rules"].items():
        settings = settings or {}
        if settings.get("enabled", True) is False:
            continue
        result.rules_run.append(name)
        for address, message in RULES[name](resources, settings, context):
            violation = Violation(name, settings.get("severity", "error"), address, message)
            exemption = _matching_exemption(violation, exemptions, today, used, result.notes)
            if exemption:
                violation.exempted_by = f"{exemption['reason']} (until {exemption['expires']})"
            result.violations.append(violation)

    for index, exemption in enumerate(exemptions):
        if index not in used and dt.date.fromisoformat(str(exemption["expires"])) >= today:
            result.notes.append(f"exemption for {exemption['address']} ({exemption['rule']}) was not needed; remove it?")
    result.notes = list(dict.fromkeys(result.notes))  # no duplicates, keep order
    return result
