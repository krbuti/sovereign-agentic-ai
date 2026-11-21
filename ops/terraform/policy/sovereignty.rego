# conftest policy for `terraform show -json plan.tfplan > plan.json`
# Run: conftest test --policy policy/ plan.json
package main

import rego.v1

eu_regions := {"eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2"}

gcp_eu_prefixes := ["europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9", "europe-north1", "europe-southwest1", "europe-central2", "eu"]

changes contains rc if {
	some rc in input.resource_changes
	some action in rc.change.actions
	action in {"create", "update"}
}

# 1. AWS provider region must be EU (constant value in provider config).
deny contains msg if {
	some name, cfg in input.configuration.provider_config
	cfg.name == "aws"
	region := cfg.expressions.region.constant_value
	not region in eu_regions
	msg := sprintf("provider %s pinned to non-EU region %s", [name, region])
}

# 2. KMS keys must rotate.
deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_key"
	not rc.change.after.enable_key_rotation
	msg := sprintf("%s: enable_key_rotation must be true", [rc.address])
}

# 3. S3 SSE must use aws:kms with an explicit CMK (no SSE-S3 / AWS-managed key).
deny contains msg if {
	some rc in changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	some rule in rc.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm != "aws:kms"
	msg := sprintf("%s: sse_algorithm must be aws:kms", [rc.address])
}

# 4. Every S3 bucket needs a public access block with all four flags.
deny contains msg if {
	some rc in changes
	rc.type == "aws_s3_bucket_public_access_block"
	some flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	not rc.change.after[flag]
	msg := sprintf("%s: %s must be true", [rc.address, flag])
}

# 5. Google resources with a location must be in the EU.
deny contains msg if {
	some rc in changes
	startswith(rc.type, "google_")
	loc := lower(object.get(rc.change.after, "location", object.get(rc.change.after, "region", "")))
	loc != ""
	not gcp_eu(loc)
	msg := sprintf("%s: location %s is outside the EU", [rc.address, loc])
}

gcp_eu(loc) if {
	some p in gcp_eu_prefixes
	startswith(loc, p)
}

# 6. No plaintext secrets in plan: flag suspicious attribute names with literal values.
deny contains msg if {
	some rc in changes
	some k, v in rc.change.after
	regex.match(`(?i)(password|secret|api_key|token)$`, k)
	is_string(v)
	v != ""
	msg := sprintf("%s: attribute %s carries a literal secret; use a secrets manager reference", [rc.address, k])
}
