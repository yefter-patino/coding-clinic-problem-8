### ❌ Terraform policy check: FAILED

| | Rule | Resource | Problem |
|---|---|---|---|
| 🔴 error | `no-public-storage` | `aws_s3_bucket_acl.public_site` | bucket ACL is 'public-read' (public) |
| 🔴 error | `no-public-storage` | `aws_s3_bucket_policy.public_site` | bucket policy allows Principal "*" without a Condition |
| 🔴 error | `no-public-storage` | `azurerm_storage_account.data` | allow_nested_items_to_be_public = true (anonymous blob access) |
| 🔴 error | `no-public-storage` | `aws_s3_bucket.public_site` | S3 bucket has no aws_s3_bucket_public_access_block in this plan |
| 🔴 error | `required-tags` | `aws_s3_bucket.public_site` | tag Environment='production' is not one of ['dev', 'stage', 'prod'] |
| 🔴 error | `required-tags` | `aws_s3_bucket.public_site` | missing required tag 'CostCenter' |
| 🔴 error | `required-tags` | `azurerm_storage_account.data` | missing required tag 'Environment' |
| 🔴 error | `required-tags` | `azurerm_storage_account.data` | missing required tag 'CostCenter' |
| 🔴 error | `no-open-ingress` | `aws_security_group.admin` | ingress rule opens port(s) [22] to the whole internet |
| 🔴 error | `no-open-ingress` | `azurerm_network_security_rule.rdp` | NSG rule 'allow-rdp' opens port(s) [3389] to the internet |
| 🔴 error | `encryption-at-rest` | `aws_db_instance.reports` | storage_encrypted must be true |
| 🟠 warning | `allowed-sizes` | `aws_db_instance.reports` | instance_class 'db.r6i.4xlarge' is not in the allowed list |
| 🔴 error | `no-destroy` | `aws_db_instance.legacy` | would be destroyed; data may be lost |
| 🔴 error | `cost-limits` | `(cost)` | monthly total 742.18 USD is over the limit of 500.00 |
| 🔴 error | `cost-limits` | `(cost)` | monthly increase 440.78 USD is over the limit of 100.00 |
| 🔴 error | `cost-limits` | `aws_db_instance.reports` | costs 583.44 USD/month, over 200.00 |

_8 resources, rules: no-public-storage, required-tags, no-open-ingress, encryption-at-rest, allowed-sizes, no-destroy, cost-limits_
