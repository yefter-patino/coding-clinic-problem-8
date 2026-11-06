"""Each rule, with small hand-made plans in the real `terraform show -json` shape."""

import datetime as dt
import json

import pytest

from helpers import GOOD_TAGS, bucket, change, pab, pab_config, plan
from tfpolicy.engine import evaluate
from tfpolicy.plan import load_plan


def run(tmp_path, plan_doc, rules, infracost=None, exemptions=None, fail_on="error", today=dt.date(2026, 10, 23)):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan_doc))
    policy = {"version": 1, "fail_on": fail_on, "rules": rules, "exemptions": exemptions or []}
    return evaluate(load_plan(path), policy, infracost, today)


def messages(result):
    return [(v.rule, v.address, v.message) for v in result.active]


# ---------------------------------------------------------------- no-public-storage
STORAGE = {"no-public-storage": {}}


def test_bucket_with_a_linked_public_access_block_passes(tmp_path):
    result = run(tmp_path, plan(bucket(), pab(), config_resources=[pab_config()]), STORAGE)
    assert messages(result) == []


def test_bucket_without_public_access_block_fails(tmp_path):
    result = run(tmp_path, plan(bucket()), STORAGE)
    assert messages(result) == [
        ("no-public-storage", "aws_s3_bucket.logs", "S3 bucket has no aws_s3_bucket_public_access_block in this plan")
    ]


def test_public_access_block_for_ANOTHER_bucket_does_not_count(tmp_path):
    doc = plan(
        bucket(),
        bucket("aws_s3_bucket.other", "yefter-other"),
        pab(),
        config_resources=[pab_config(bucket_address="aws_s3_bucket.other")],
    )
    assert [a for _, a, _ in messages(run(tmp_path, doc, STORAGE))] == ["aws_s3_bucket.logs"]


def test_public_access_block_can_be_linked_by_bucket_name(tmp_path):
    assert messages(run(tmp_path, plan(bucket(), pab(bucket_name="yefter-logs")), STORAGE)) == []


def test_link_works_inside_modules_and_with_count(tmp_path):
    doc = plan(
        bucket("module.storage.aws_s3_bucket.logs[0]"),
        pab("module.storage.aws_s3_bucket_public_access_block.logs[0]"),
        module_calls={"storage": {"module": {"resources": [pab_config()]}}},
    )
    assert messages(run(tmp_path, doc, STORAGE)) == []


def test_requirement_can_be_switched_off(tmp_path):
    assert messages(run(tmp_path, plan(bucket()), {"no-public-storage": {"require_s3_public_access_block": False}})) == []


@pytest.mark.parametrize("acl, bad", [("private", False), ("public-read", True), ("public-read-write", True)])
def test_public_acls(tmp_path, acl, bad):
    doc = plan(change("aws_s3_bucket_acl.a", "aws_s3_bucket_acl", {"bucket": "b", "acl": acl}))
    result = run(tmp_path, doc, {"no-public-storage": {"require_s3_public_access_block": False}})
    assert bool(messages(result)) is bad


def test_public_access_block_with_a_setting_off_fails(tmp_path):
    doc = plan(bucket(), pab(block_public_policy=False), config_resources=[pab_config()])
    assert "block_public_policy = false" in messages(run(tmp_path, doc, STORAGE))[0][2]


@pytest.mark.parametrize(
    "statement, bad",
    [
        ({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}, True),
        ({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}, True),
        (
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
            },
            False,
        ),
        ({"Effect": "Deny", "Principal": "*", "Action": "s3:*"}, False),
        ({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "s3:GetObject"}, False),
    ],
)
def test_bucket_policies(tmp_path, statement, bad):
    policy = json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    doc = plan(change("aws_s3_bucket_policy.p", "aws_s3_bucket_policy", {"bucket": "b", "policy": policy}))
    result = run(tmp_path, doc, {"no-public-storage": {"require_s3_public_access_block": False}})
    assert bool(messages(result)) is bad


def test_azure_public_blob_access_and_containers(tmp_path):
    doc = plan(
        change("azurerm_storage_account.ok", "azurerm_storage_account", {"allow_nested_items_to_be_public": False}),
        change("azurerm_storage_account.bad", "azurerm_storage_account", {"allow_nested_items_to_be_public": True}),
        change("azurerm_storage_container.c", "azurerm_storage_container", {"container_access_type": "blob"}),
    )
    assert [a for _, a, _ in messages(run(tmp_path, doc, STORAGE))] == [
        "azurerm_storage_account.bad",
        "azurerm_storage_container.c",
    ]


# ---------------------------------------------------------------- required-tags
TAGS = {"required-tags": {"tags": {"Owner": {}, "Environment": ["dev", "prod"], "CostCenter": {"pattern": "^CC-[0-9]{4}$"}}}}


def test_all_tags_present_passes(tmp_path):
    assert messages(run(tmp_path, plan(bucket()), TAGS)) == []


def test_missing_wrong_value_and_bad_pattern(tmp_path):
    tags = {"Owner": "", "Environment": "qa", "CostCenter": "1234"}
    found = [m for _, _, m in messages(run(tmp_path, plan(bucket(tags=tags)), TAGS))]
    assert found == [
        "missing required tag 'Owner'",
        "tag Environment='qa' is not one of ['dev', 'prod']",
        "tag CostCenter='1234' does not match ^CC-[0-9]{4}$",
    ]


def test_provider_default_tags_count_through_tags_all(tmp_path):
    doc = plan(change("aws_sqs_queue.q", "aws_sqs_queue", {"tags": {}, "tags_all": GOOD_TAGS}))
    assert messages(run(tmp_path, doc, TAGS)) == []


def test_tags_are_used_when_tags_all_is_unknown(tmp_path):
    doc = plan(
        change("aws_sqs_queue.q", "aws_sqs_queue", {"tags": GOOD_TAGS, "tags_all": None}, after_unknown={"tags_all": True})
    )
    assert messages(run(tmp_path, doc, TAGS)) == []


def test_resources_without_tags_are_skipped(tmp_path):
    doc = plan(change("aws_iam_role_policy.p", "aws_iam_role_policy", {"policy": "{}"}))
    assert messages(run(tmp_path, doc, TAGS)) == []


def test_unchanged_resources_are_not_checked_by_default(tmp_path):
    doc = plan(change("aws_sqs_queue.old", "aws_sqs_queue", {"tags": {}}, actions=("no-op",)))
    assert messages(run(tmp_path, doc, TAGS)) == []
    rules = {"required-tags": {**TAGS["required-tags"], "include_unchanged": True}}
    assert messages(run(tmp_path, doc, rules))


# ---------------------------------------------------------------- no-open-ingress
INGRESS = {"no-open-ingress": {"ports": [22, 3389]}}


def sg(rule):
    return change("aws_security_group.s", "aws_security_group", {"ingress": [rule], "tags": GOOD_TAGS})


@pytest.mark.parametrize(
    "rule, bad",
    [
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}, True),
        ({"from_port": 0, "to_port": 65535, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}, True),
        ({"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}, True),
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "ipv6_cidr_blocks": ["::/0"]}, True),
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}, False),
        ({"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}, False),
    ],
)
def test_security_group_inline_rules(tmp_path, rule, bad):
    assert bool(messages(run(tmp_path, plan(sg(rule)), INGRESS))) is bad


def test_separate_rule_resources(tmp_path):
    doc = plan(
        change(
            "aws_vpc_security_group_ingress_rule.ssh",
            "aws_vpc_security_group_ingress_rule",
            {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
        ),
        change(
            "aws_security_group_rule.rdp",
            "aws_security_group_rule",
            {"type": "ingress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 3389, "to_port": 3389, "protocol": "tcp"},
        ),
        change(
            "aws_security_group_rule.out",
            "aws_security_group_rule",
            {"type": "egress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0, "protocol": "-1"},
        ),
    )
    assert [a for _, a, _ in messages(run(tmp_path, doc, INGRESS))] == [
        "aws_vpc_security_group_ingress_rule.ssh",
        "aws_security_group_rule.rdp",
    ]


@pytest.mark.parametrize(
    "rule, bad",
    [
        ({"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}, True),
        (
            {
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "Internet",
                "destination_port_range": "3000-4000",
            },
            True,
        ),
        (
            {
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "0.0.0.0/0",
                "destination_port_ranges": ["80", "*"],
            },
            True,
        ),
        ({"direction": "Inbound", "access": "Deny", "source_address_prefix": "*", "destination_port_range": "22"}, False),
        ({"direction": "Outbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}, False),
        (
            {"direction": "Inbound", "access": "Allow", "source_address_prefix": "10.0.0.0/8", "destination_port_range": "22"},
            False,
        ),
    ],
)
def test_azure_nsg_rules(tmp_path, rule, bad):
    doc = plan(change("azurerm_network_security_rule.r", "azurerm_network_security_rule", {"name": "r", **rule}))
    assert bool(messages(run(tmp_path, doc, INGRESS))) is bad


def test_azure_nsg_inline_rules(tmp_path):
    nsg = {
        "security_rule": [
            {
                "name": "ssh",
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "*",
                "destination_port_range": "22",
            }
        ],
        "tags": GOOD_TAGS,
    }
    doc = plan(change("azurerm_network_security_group.n", "azurerm_network_security_group", nsg))
    assert "NSG rule 'ssh'" in messages(run(tmp_path, doc, INGRESS))[0][2]


# ---------------------------------------------------------------- encryption, sizes, destroy
def test_encryption(tmp_path):
    doc = plan(
        change("aws_ebs_volume.ok", "aws_ebs_volume", {"encrypted": True}),
        change("aws_ebs_volume.bad", "aws_ebs_volume", {"encrypted": False}),
        change("aws_rds_cluster.unknown", "aws_rds_cluster", {}, after_unknown={"storage_encrypted": True}),
    )
    assert [a for _, a, _ in messages(run(tmp_path, doc, {"encryption-at-rest": {}}))] == ["aws_ebs_volume.bad"]


def test_allowed_sizes_with_wildcards(tmp_path):
    doc = plan(
        change("aws_instance.ok", "aws_instance", {"instance_type": "t3.small"}),
        change("aws_instance.big", "aws_instance", {"instance_type": "p5.48xlarge"}),
        change("azurerm_linux_virtual_machine.vm", "azurerm_linux_virtual_machine", {"size": "Standard_D2s_v5"}),
    )
    rules = {"allowed-sizes": {"allowed": ["t3.*", "Standard_D*s_v5"]}}
    assert [a for _, a, _ in messages(run(tmp_path, doc, rules))] == ["aws_instance.big"]


def test_destroy_and_replace_of_protected_types(tmp_path):
    doc = plan(
        change("aws_db_instance.gone", "aws_db_instance", None, actions=("delete",)),
        change("aws_db_instance.replaced", "aws_db_instance", {"storage_encrypted": True}, actions=("delete", "create")),
        change("aws_instance.gone", "aws_instance", None, actions=("delete",)),
    )
    found = messages(run(tmp_path, doc, {"no-destroy": {"types": ["aws_db_*"]}}))
    assert [(a, m) for _, a, m in found] == [
        ("aws_db_instance.gone", "would be destroyed; data may be lost"),
        ("aws_db_instance.replaced", "would be replaced (destroyed, then created again); data may be lost"),
    ]


# ---------------------------------------------------------------- cost-limits
INFRACOST = {
    "currency": "USD",
    "totalMonthlyCost": "420.00",
    "pastTotalMonthlyCost": "300.00",
    "diffTotalMonthlyCost": "120.00",
    "projects": [
        {
            "breakdown": {
                "resources": [
                    {"name": "aws_db_instance.a", "monthlyCost": "250.5"},
                    {"name": "aws_s3_bucket.b", "monthlyCost": None},
                ]
            }
        }
    ],
}


def test_cost_limits(tmp_path):
    rules = {"cost-limits": {"max_monthly_total": 400, "max_monthly_increase": 100, "max_resource_monthly": 200}}
    found = [m for _, _, m in messages(run(tmp_path, plan(), rules, infracost=INFRACOST))]
    assert found == [
        "monthly total 420.00 USD is over the limit of 400.00",
        "monthly increase 120.00 USD is over the limit of 100.00",
        "costs 250.50 USD/month, over 200.00",
    ]


def test_cost_within_limits(tmp_path):
    rules = {"cost-limits": {"max_monthly_total": 1000, "max_monthly_increase": 500}}
    assert messages(run(tmp_path, plan(), rules, infracost=INFRACOST)) == []


def test_cost_without_infracost_is_a_note_not_a_failure(tmp_path):
    result = run(tmp_path, plan(), {"cost-limits": {"max_monthly_total": 1}})
    assert not result.failed
    assert "cost-limits skipped" in result.notes[0]
