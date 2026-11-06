"""Read the JSON that `terraform show -json plan.out` prints."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Resource:
    address: str  # module.net.aws_s3_bucket.logs[0]
    type: str  # aws_s3_bucket
    actions: list[str]  # ["create"], ["update"], ["delete", "create"], ["no-op"], ...
    after: dict = field(default_factory=dict)  # values after apply (empty when deleted)
    after_unknown: dict = field(default_factory=dict)  # true where the value is only known after apply
    before: dict = field(default_factory=dict)
    module: str = ""  # module.net ("" for the root module)
    references: dict = field(default_factory=dict)  # argument -> addresses it references in the code

    @property
    def is_deleted(self) -> bool:
        return "delete" in self.actions

    @property
    def is_changed(self) -> bool:
        """Created or updated (a replacement counts too)."""
        return "create" in self.actions or "update" in self.actions

    def is_unknown(self, key: str) -> bool:
        return bool(self.after_unknown.get(key))


class PlanError(ValueError):
    pass


def _strip_index(address: str) -> str:
    """aws_s3_bucket.b["x"] -> aws_s3_bucket.b   (config addresses have no index)"""
    return re.sub(r"\[[^\]]*\]$", "", address)


def _config_references(plan: dict) -> dict[str, dict]:
    """{full config address: {argument: [referenced addresses]}} from the plan's "configuration" part."""
    found: dict[str, dict] = {}

    def walk(module: dict, prefix: str) -> None:
        for resource in module.get("resources", []):
            refs = {}
            for argument, expression in (resource.get("expressions") or {}).items():
                if isinstance(expression, dict) and expression.get("references"):
                    refs[argument] = [f"{prefix}{r}" for r in expression["references"]]
            found[f"{prefix}{resource['address']}"] = refs
        for name, call in (module.get("module_calls") or {}).items():
            walk(call.get("module", {}), f"{prefix}module.{name}.")

    walk(plan.get("configuration", {}).get("root_module", {}), "")
    return found


def load_plan(path: str | Path) -> list[Resource]:
    try:
        plan = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise PlanError(f"cannot read the plan JSON {path}: {err}") from err
    if "resource_changes" not in plan and "format_version" not in plan:
        raise PlanError(f"{path} does not look like `terraform show -json` output")

    references = _config_references(plan)
    resources = []
    for rc in plan.get("resource_changes") or []:
        if rc.get("mode") != "managed":  # data sources are only read, never created
            continue
        change = rc.get("change") or {}
        address = rc["address"]
        resources.append(
            Resource(
                address=address,
                type=rc["type"],
                actions=list(change.get("actions") or []),
                after=change.get("after") or {},
                after_unknown=change.get("after_unknown") or {},
                before=change.get("before") or {},
                module=rc.get("module_address", ""),
                references=references.get(_strip_index(address), {}),
            )
        )
    return resources
