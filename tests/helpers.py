"""Build small plan JSON documents in the same shape as `terraform show -json` (format 1.2)."""

GOOD_TAGS = {"Owner": "yefter", "Environment": "prod", "CostCenter": "CC-1234", "ManagedBy": "terraform"}


def change(address, rtype, after, actions=("create",), after_unknown=None, before=None, module=""):
    rc = {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": address.split(".")[-1].split("[")[0],
        "provider_name": "registry.terraform.io/hashicorp/aws"
        if rtype.startswith("aws")
        else "registry.terraform.io/hashicorp/azurerm",
        "change": {
            "actions": list(actions),
            "before": before,
            "after": after,
            "after_unknown": after_unknown or {},
        },
    }
    if module:
        rc["module_address"] = module
    return rc


def plan(*changes, config_resources=None, module_calls=None):
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.0",
        "resource_changes": list(changes),
        "configuration": {"root_module": {"resources": config_resources or [], "module_calls": module_calls or {}}},
    }


def bucket(address="aws_s3_bucket.logs", name="yefter-logs", tags=None):
    return change(address, "aws_s3_bucket", {"bucket": name, "tags": tags or GOOD_TAGS, "tags_all": tags or GOOD_TAGS})


def pab(address="aws_s3_bucket_public_access_block.logs", bucket_name=None, **settings):
    after = {key: True for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")}
    after.update(settings)
    unknown = {}
    if bucket_name:
        after["bucket"] = bucket_name
    else:
        unknown["bucket"] = True  # the usual case: bucket = aws_s3_bucket.x.id, only known after apply
    return change(address, "aws_s3_bucket_public_access_block", after, after_unknown=unknown)


def pab_config(pab_address="aws_s3_bucket_public_access_block.logs", bucket_address="aws_s3_bucket.logs"):
    """The configuration part that says: this public access block's `bucket` refers to that bucket."""
    rtype, name = pab_address.rsplit(".", 1)
    return {
        "address": pab_address,
        "mode": "managed",
        "type": rtype,
        "name": name,
        "expressions": {"bucket": {"references": [f"{bucket_address}.id", bucket_address]}},
    }
