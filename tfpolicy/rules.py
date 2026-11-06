"""The rules. Each rule is a small function:

    rule(resources, params, context) -> list of (address, message)

`params` comes from the policy file, so limits and lists are never hardcoded here.
To add a rule: write a function, then add it to RULES at the bottom.
"""

from __future__ import annotations

import fnmatch
import json
import re
from decimal import Decimal, InvalidOperation

from tfpolicy.plan import Resource

Finding = tuple[str, str]  # (resource address, message)

OPEN_TO_WORLD = {"0.0.0.0/0", "::/0", "*", "internet", "any"}


def _changed(resources, types=None, include_unchanged=False):
    """Resources that will exist after apply and are new or modified (optionally of some types)."""
    for r in resources:
        if r.is_deleted and not r.is_changed:
            continue
        if not include_unchanged and not r.is_changed:
            continue
        if types is None or r.type in types:
            yield r


# ---------------------------------------------------------------- storage must not be public

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
PAB_SETTINGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


def _bucket_of(resource: Resource) -> set[str]:
    """Which bucket a bucket-level resource (ACL, policy, public access block) belongs to:
    the bucket name if known, plus the bucket resource address it references in the code."""
    keys = set()
    if isinstance(resource.after.get("bucket"), str):
        keys.add(resource.after["bucket"])
    for ref in resource.references.get("bucket", []):
        keys.add(re.sub(r"\.(id|bucket|arn)$", "", ref))
    return keys


def _policy_allows_everyone(policy_text) -> bool:
    try:
        policy = json.loads(policy_text) if isinstance(policy_text, str) else policy_text
    except json.JSONDecodeError:
        return False
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        principal = statement.get("Principal")
        everyone = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
        if statement.get("Effect") == "Allow" and everyone and not statement.get("Condition"):
            return True
    return False


def no_public_storage(resources, params, context) -> list[Finding]:
    findings = []
    changed = list(_changed(resources, include_unchanged=params.get("include_unchanged", False)))

    for r in changed:
        if r.type == "aws_s3_bucket_acl" and r.after.get("acl") in PUBLIC_ACLS:
            findings.append((r.address, f"bucket ACL is '{r.after['acl']}' (public)"))
        if r.type == "aws_s3_bucket_policy" and _policy_allows_everyone(r.after.get("policy")):
            findings.append((r.address, 'bucket policy allows Principal "*" without a Condition'))
        if r.type == "aws_s3_bucket_public_access_block":
            off = [s for s in PAB_SETTINGS if r.after.get(s) is False]
            if off:
                findings.append((r.address, f"public access block has {', '.join(off)} = false"))
        if r.type == "azurerm_storage_account" and r.after.get("allow_nested_items_to_be_public") is True:
            findings.append((r.address, "allow_nested_items_to_be_public = true (anonymous blob access)"))
        if r.type == "azurerm_storage_container" and r.after.get("container_access_type") in ("blob", "container"):
            findings.append((r.address, f"container_access_type = '{r.after['container_access_type']}' (public)"))

    if params.get("require_s3_public_access_block", True):
        blocked = set()
        for r in resources:
            if r.type == "aws_s3_bucket_public_access_block" and not r.is_deleted:
                blocked |= _bucket_of(r)
        for bucket in (r for r in changed if r.type == "aws_s3_bucket"):
            keys = {re.sub(r"\[[^\]]*\]$", "", bucket.address)}
            if isinstance(bucket.after.get("bucket"), str):
                keys.add(bucket.after["bucket"])
            if not keys & blocked:
                findings.append((bucket.address, "S3 bucket has no aws_s3_bucket_public_access_block in this plan"))
    return findings


# ---------------------------------------------------------------- required tags


def required_tags(resources, params, context) -> list[Finding]:
    """Every taggable resource must carry the listed tags (and allowed values / pattern, if given).

    tags_all (AWS, includes provider default_tags) is used when known, otherwise tags.
    """
    wanted: dict = params.get("tags") or {}
    skip_types = set(params.get("skip_types") or [])
    findings = []
    for r in _changed(resources, include_unchanged=params.get("include_unchanged", False)):
        if r.type in skip_types or "tags" not in r.after:
            continue  # not a taggable resource
        if "tags_all" in r.after and not r.is_unknown("tags_all"):
            tags = r.after.get("tags_all") or {}
        else:
            tags = r.after.get("tags") or {}
        for key, rule in wanted.items():
            if key not in tags or tags[key] in ("", None):
                findings.append((r.address, f"missing required tag '{key}'"))
                continue
            value = str(tags[key])
            if isinstance(rule, list) and value not in [str(v) for v in rule]:
                findings.append((r.address, f"tag {key}='{value}' is not one of {rule}"))
            elif isinstance(rule, dict) and "pattern" in rule and not re.fullmatch(rule["pattern"], value):
                findings.append((r.address, f"tag {key}='{value}' does not match {rule['pattern']}"))
    return findings


# ---------------------------------------------------------------- no admin ports open to the internet


def _covers(port: int, from_port, to_port, protocol) -> bool:
    if str(protocol) in ("-1", "all"):
        return True
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def _azure_covers(port: int, ranges) -> bool:
    for item in ranges:
        item = str(item).strip()
        if item == "*":
            return True
        low, _, high = item.partition("-")
        try:
            if int(low) <= port <= int(high or low):
                return True
        except ValueError:
            continue
    return False


def no_open_ingress(resources, params, context) -> list[Finding]:
    ports = [int(p) for p in params.get("ports", [22, 3389])]
    findings = []

    def check(address, cidrs, from_port, to_port, protocol, label):
        if {str(c).lower() for c in cidrs or []} & OPEN_TO_WORLD:
            hit = [p for p in ports if _covers(p, from_port, to_port, protocol)]
            if hit:
                findings.append((address, f"{label} opens port(s) {hit} to the whole internet"))

    for r in _changed(resources, include_unchanged=params.get("include_unchanged", False)):
        a = r.after
        if r.type == "aws_security_group":
            for rule in a.get("ingress") or []:
                cidrs = (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
                check(r.address, cidrs, rule.get("from_port"), rule.get("to_port"), rule.get("protocol"), "ingress rule")
        elif r.type == "aws_security_group_rule" and a.get("type") == "ingress":
            cidrs = (a.get("cidr_blocks") or []) + (a.get("ipv6_cidr_blocks") or [])
            check(r.address, cidrs, a.get("from_port"), a.get("to_port"), a.get("protocol"), "rule")
        elif r.type == "aws_vpc_security_group_ingress_rule":
            cidrs = [a.get("cidr_ipv4"), a.get("cidr_ipv6")]
            check(r.address, cidrs, a.get("from_port"), a.get("to_port"), a.get("ip_protocol"), "rule")
        elif r.type in ("azurerm_network_security_rule", "azurerm_network_security_group"):
            rules = (a.get("security_rule") or []) if r.type == "azurerm_network_security_group" else [a]
            for rule in rules:
                if str(rule.get("direction", "")).lower() != "inbound" or str(rule.get("access", "")).lower() != "allow":
                    continue
                sources = [rule.get("source_address_prefix")] + list(rule.get("source_address_prefixes") or [])
                if {str(s).lower() for s in sources if s} & OPEN_TO_WORLD:
                    ranges = [rule.get("destination_port_range")] + list(rule.get("destination_port_ranges") or [])
                    hit = [p for p in ports if _azure_covers(p, [x for x in ranges if x])]
                    if hit:
                        findings.append((r.address, f"NSG rule '{rule.get('name')}' opens port(s) {hit} to the internet"))
    return findings


# ---------------------------------------------------------------- encryption at rest

ENCRYPTION_SETTINGS = {
    "aws_db_instance": ("storage_encrypted", True),
    "aws_rds_cluster": ("storage_encrypted", True),
    "aws_ebs_volume": ("encrypted", True),
    "aws_efs_file_system": ("encrypted", True),
    "azurerm_managed_disk": None,  # encrypted by the platform; nothing to check
}


def encryption_at_rest(resources, params, context) -> list[Finding]:
    findings = []
    for r in _changed(resources, types=set(ENCRYPTION_SETTINGS), include_unchanged=params.get("include_unchanged", False)):
        setting = ENCRYPTION_SETTINGS[r.type]
        if setting and not r.is_unknown(setting[0]) and r.after.get(setting[0]) is not setting[1]:
            findings.append((r.address, f"{setting[0]} must be true"))
    return findings


# ---------------------------------------------------------------- allowed sizes

SIZE_FIELDS = {
    "aws_instance": "instance_type",
    "aws_launch_template": "instance_type",
    "aws_db_instance": "instance_class",
    "azurerm_linux_virtual_machine": "size",
    "azurerm_windows_virtual_machine": "size",
}


def allowed_sizes(resources, params, context) -> list[Finding]:
    allowed = params.get("allowed") or []
    findings = []
    for r in _changed(resources, types=set(SIZE_FIELDS)):
        value = r.after.get(SIZE_FIELDS[r.type])
        if value and not any(fnmatch.fnmatch(value, pattern) for pattern in allowed):
            findings.append((r.address, f"{SIZE_FIELDS[r.type]} '{value}' is not in the allowed list"))
    return findings


# ---------------------------------------------------------------- protected resources are not destroyed


def no_destroy(resources, params, context) -> list[Finding]:
    protected = params.get("types") or []
    findings = []
    for r in resources:
        if r.is_deleted and any(fnmatch.fnmatch(r.type, pattern) for pattern in protected):
            what = "replaced (destroyed, then created again)" if r.is_changed else "destroyed"
            findings.append((r.address, f"would be {what}; data may be lost"))
    return findings


# ---------------------------------------------------------------- cost limits (Infracost JSON)


def _money(value) -> Decimal | None:
    if value in (None, ""):
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def cost_limits(resources, params, context) -> list[Finding]:
    """Uses the output of `infracost breakdown --path plan.json --format json`."""
    infracost = context.get("infracost")
    if infracost is None:
        context.setdefault("notes", []).append("cost-limits skipped: no Infracost JSON given (--infracost)")
        return []
    currency = infracost.get("currency", "USD")
    findings = []
    total = _money(infracost.get("totalMonthlyCost"))
    past = _money(infracost.get("pastTotalMonthlyCost")) or Decimal(0)
    increase = _money(infracost.get("diffTotalMonthlyCost")) if "diffTotalMonthlyCost" in infracost else None
    if increase is None and total is not None:
        increase = total - past

    limit = _money(params.get("max_monthly_total"))
    if limit is not None and total is not None and total > limit:
        findings.append(("(cost)", f"monthly total {total:.2f} {currency} is over the limit of {limit:.2f}"))
    limit = _money(params.get("max_monthly_increase"))
    if limit is not None and increase is not None and increase > limit:
        findings.append(("(cost)", f"monthly increase {increase:.2f} {currency} is over the limit of {limit:.2f}"))
    limit = _money(params.get("max_resource_monthly"))
    if limit is not None:
        for project in infracost.get("projects") or []:
            for item in (project.get("breakdown") or {}).get("resources") or []:
                cost = _money(item.get("monthlyCost"))
                if cost is not None and cost > limit:
                    findings.append((item.get("name", "?"), f"costs {cost:.2f} {currency}/month, over {limit:.2f}"))
    return findings


RULES = {
    "no-public-storage": no_public_storage,
    "required-tags": required_tags,
    "no-open-ingress": no_open_ingress,
    "encryption-at-rest": encryption_at_rest,
    "allowed-sizes": allowed_sizes,
    "no-destroy": no_destroy,
    "cost-limits": cost_limits,
}
