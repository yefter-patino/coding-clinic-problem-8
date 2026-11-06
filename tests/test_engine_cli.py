"""Policy loading, exemptions, pass/fail, and the command line."""

import datetime as dt
import json
from pathlib import Path

import pytest

from helpers import bucket, plan
from tfpolicy.cli import main
from tfpolicy.engine import PolicyError, evaluate, load_policy
from tfpolicy.plan import load_plan

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
DEFAULT_POLICY = ROOT / "policies" / "default.yaml"


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def bucket_plan(tmp_path):
    return load_plan(write(tmp_path, "plan.json", json.dumps(plan(bucket()))))


# ---------------------------------------------------------------- exemptions
def exempt(expires, address="aws_s3_bucket.*", rule="no-public-storage"):
    return {"rule": rule, "address": address, "reason": "static website, reviewed", "expires": expires}


def test_a_valid_exemption_turns_the_violation_off(tmp_path):
    policy = {"version": 1, "rules": {"no-public-storage": {}}, "exemptions": [exempt("2026-12-31")]}
    result = evaluate(bucket_plan(tmp_path), policy, today=dt.date(2026, 10, 23))
    assert not result.failed
    assert result.violations[0].exempted_by == "static website, reviewed (until 2026-12-31)"


def test_an_expired_exemption_stops_working_and_says_so(tmp_path):
    policy = {"version": 1, "rules": {"no-public-storage": {}}, "exemptions": [exempt("2026-10-01")]}
    result = evaluate(bucket_plan(tmp_path), policy, today=dt.date(2026, 10, 23))
    assert result.failed
    assert "EXPIRED on 2026-10-01" in result.notes[0]


def test_an_exemption_that_is_not_needed_is_reported(tmp_path):
    policy = {
        "version": 1,
        "rules": {"no-public-storage": {}},
        "exemptions": [exempt("2026-12-31", address="aws_s3_bucket.something_else")],
    }
    result = evaluate(bucket_plan(tmp_path), policy, today=dt.date(2026, 10, 23))
    assert result.failed
    assert any("was not needed" in note for note in result.notes)


def test_warnings_fail_only_when_fail_on_is_warning(tmp_path):
    rules = {"no-public-storage": {"severity": "warning"}}
    assert not evaluate(bucket_plan(tmp_path), {"version": 1, "rules": rules}).failed
    assert evaluate(bucket_plan(tmp_path), {"version": 1, "rules": rules, "fail_on": "warning"}).failed


def test_a_disabled_rule_does_not_run(tmp_path):
    result = evaluate(bucket_plan(tmp_path), {"version": 1, "rules": {"no-public-storage": {"enabled": False}}})
    assert result.rules_run == [] and not result.violations


# ---------------------------------------------------------------- policy file checks
@pytest.mark.parametrize(
    "text, problem",
    [
        ("rules: {required-tags: {}}", "version: 1"),
        ("version: 1\nrules: {}", "at least one rule"),
        ("version: 1\nrules: {no-such-rule: {}}", "unknown rule"),
        ("version: 1\nrules: {required-tags: {severity: fatal}}", "severity"),
        ("version: 1\nfail_on: always\nrules: {required-tags: {}}", "fail_on"),
        ("version: 1\nrules: {required-tags: {}}\nexemptions: [{rule: x, address: y, expires: 2026-01-01}]", "reason"),
        ("version: 1\nrules: {required-tags: {}}\nexemptions: [{rule: x, address: y, reason: z, expires: soon}]", "YYYY-MM-DD"),
        ("version: 1\nrules: [", "cannot read"),
    ],
)
def test_bad_policy_files_are_refused(tmp_path, text, problem):
    with pytest.raises(PolicyError, match=problem):
        load_policy(write(tmp_path, "policy.yaml", text))


def test_the_shipped_default_policy_is_valid():
    assert "required-tags" in load_policy(DEFAULT_POLICY)["rules"]


# ---------------------------------------------------------------- command line
def test_compliant_plan_exits_0(capsys):
    assert main([str(EXAMPLES / "plan-compliant.json"), "--policy", str(DEFAULT_POLICY)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_violating_plan_exits_1_and_lists_every_rule(capsys):
    code = main(
        [str(EXAMPLES / "plan-violations.json"), "--policy", str(DEFAULT_POLICY), "--infracost", str(EXAMPLES / "infracost.json")]
    )
    out = capsys.readouterr().out
    assert code == 1
    for rule in (
        "no-public-storage",
        "required-tags",
        "no-open-ingress",
        "encryption-at-rest",
        "allowed-sizes",
        "no-destroy",
        "cost-limits",
    ):
        assert rule in out


def test_json_and_markdown_reports(tmp_path, capsys):
    md = tmp_path / "report.md"
    code = main(
        [
            str(EXAMPLES / "plan-violations.json"),
            "--policy",
            str(DEFAULT_POLICY),
            "--format",
            "json",
            "--markdown-output",
            str(md),
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == 1 and data["passed"] is False and len(data["violations"]) > 5
    assert md.read_text().startswith("### ❌ Terraform policy check: FAILED")


def test_bad_input_exits_2(tmp_path, capsys):
    assert main([str(write(tmp_path, "x.json", "not json")), "--policy", str(DEFAULT_POLICY)]) == 2
    assert main([str(write(tmp_path, "y.json", "{}")), "--policy", str(DEFAULT_POLICY)]) == 2
    assert main([str(EXAMPLES / "plan-compliant.json"), "--policy", str(tmp_path / "missing.yaml")]) == 2
    assert main([]) == 2


def test_github_actions_gets_annotations_and_a_summary(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main([str(EXAMPLES / "plan-violations.json"), "--policy", str(DEFAULT_POLICY)])
    assert "::error title=Policy no-open-ingress::aws_security_group.admin" in capsys.readouterr().out
    assert "Terraform policy check" in summary.read_text()


def test_settings_from_environment(monkeypatch, capsys):
    monkeypatch.setenv("TFPOLICY_PLAN", str(EXAMPLES / "plan-compliant.json"))
    monkeypatch.setenv("TFPOLICY_POLICY", str(DEFAULT_POLICY))
    assert main([]) == 0


def test_data_sources_are_ignored(tmp_path):
    doc = plan(bucket())
    doc["resource_changes"][0]["mode"] = "data"
    assert load_plan(write(tmp_path, "p.json", json.dumps(doc))) == []
