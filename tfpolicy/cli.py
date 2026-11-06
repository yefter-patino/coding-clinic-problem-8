"""Command line:

  terraform plan -out plan.out && terraform show -json plan.out > plan.json
  python -m tfpolicy plan.json --policy policies/default.yaml [--infracost infracost.json]

Exit codes: 0 = passed, 1 = policy violated (fail the pipeline), 2 = bad input.
Every option also has an environment variable: TFPOLICY_<OPTION>.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from tfpolicy import __version__
from tfpolicy.engine import PolicyError, evaluate, load_policy
from tfpolicy.plan import PlanError, load_plan
from tfpolicy.report import FORMATS, github_annotations

EXIT_PASS, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def env(name: str, default: str = "") -> str:
    return os.environ.get(f"TFPOLICY_{name}", default)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfpolicy", description="Check a Terraform plan against a policy file.")
    p.add_argument("plan", nargs="?", default=env("PLAN"), help="plan JSON from `terraform show -json`")
    p.add_argument("--policy", default=env("POLICY", "policies/default.yaml"), help="policy YAML file")
    p.add_argument("--infracost", default=env("INFRACOST"), help="infracost breakdown --format json output")
    p.add_argument("--format", choices=sorted(FORMATS), default=env("FORMAT", "text"))
    p.add_argument("--output", default=env("OUTPUT"), help="also write the report to this file")
    p.add_argument("--markdown-output", default=env("MARKDOWN_OUTPUT"), help="write a Markdown report here (PR comment)")
    p.add_argument(
        "--fail-on", choices=["error", "warning"], default=env("FAIL_ON") or None, help="override the policy's fail_on"
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plan:
        print("error: give the plan JSON file", file=sys.stderr)
        return EXIT_ERROR
    try:
        resources = load_plan(args.plan)
        policy = load_policy(args.policy)
        if args.fail_on:
            policy["fail_on"] = args.fail_on
        infracost = None
        if args.infracost:
            try:
                infracost = json.loads(Path(args.infracost).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as err:
                raise PlanError(f"cannot read the Infracost JSON {args.infracost}: {err}") from err
        result = evaluate(resources, policy, infracost)
    except (PlanError, PolicyError) as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    report = FORMATS[args.format](result)
    print(report)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    if args.markdown_output:
        Path(args.markdown_output).write_text(FORMATS["markdown"](result) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        annotations = github_annotations(result)
        if annotations:
            print(annotations)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(FORMATS["markdown"](result) + "\n")
    return EXIT_FAIL if result.failed else EXIT_PASS
