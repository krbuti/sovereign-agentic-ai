# Terraform plan guardrails for the EU sovereign engineering-Q&A platform.
# Input: `terraform show -json plan.out > tfplan.json`
# Run:   conftest test --policy policies/rego/terraform tfplan.json
#        conftest verify --policy policies/rego/terraform
# Syntax: OPA v1 (`contains`/`if` keywords); `import rego.v1` keeps it valid on OPA 0.59+ too.
package main

import rego.v1

# Canonical "EU only" allow-list = EU MEMBER-STATE regions only (same list in
# retrieval_filter.py, eng_qa.cedar, k8s/workload_guardrails.rego):
#   AWS: Frankfurt, Ireland, Paris, Milan, Spain, Stockholm.
# NOT EU: eu-west-2 (London, UK) and eu-central-2 (Zurich, CH). Add London only
# if the customer's residency definition accepts the UK (adequacy decision) -
# e.g. because AgentCore Guardrails-in-Policy launched in London/Stockholm only.
allowed_aws_regions := {
	"eu-central-1", "eu-west-1", "eu-west-3",
	"eu-south-1", "eu-south-2", "eu-north-1",
}

#   GCP: Belgium, Frankfurt, Netherlands, Milan, Paris, Madrid, Finland, Warsaw
#        (+ the "eu" multi-region). NOT EU: europe-west2 (London), europe-west6 (Zurich).
#        Other EU-located GCP regions (e.g. europe-west10 Berlin, europe-west12 Turin)
#        are deliberately not listed; add them to every copy of the list together.
allowed_gcp_locations := {
	"eu", "europe-west1", "europe-west3", "europe-west4", "europe-west8",
	"europe-west9", "europe-north1", "europe-southwest1", "europe-central2",
}

max_rotation_days := 365

# resources being created or updated
changes contains rc if {
	some rc in input.resource_changes
	some a in rc.change.actions
	a in {"create", "update"}
}

# NB: `not known_string(x.missing)` is NOT true in Rego (undefined argument makes the
# whole call undefined), so callers wrap optional attributes in object.get(..., "").
known_string(v) if {
	is_string(v)
	v != ""
}

# ---------------------------------------------------------------- residency
deny contains msg if {
	some name, cfg in input.configuration.provider_config
	cfg.name == "aws"
	region := cfg.expressions.region.constant_value
	not region in allowed_aws_regions
	msg := sprintf("RESIDENCY: provider %q uses AWS region %q (EU allow-list only)", [name, region])
}

deny contains msg if {
	some rc in changes
	rc.type in {"google_storage_bucket", "google_kms_key_ring", "google_bigquery_dataset"}
	loc := lower(rc.change.after.location)
	not loc in allowed_gcp_locations
	msg := sprintf("RESIDENCY: %s location %q is outside EU allow-list", [rc.address, loc])
}

# ---------------------------------------------------------------- S3 + CMK
deny contains msg if {
	some rc in changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	some rule in rc.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	not d.sse_algorithm in {"aws:kms", "aws:kms:dsse"}
	msg := sprintf("CMK: %s uses %q; require SSE-KMS with a customer managed key", [rc.address, d.sse_algorithm])
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	some i, rule in rc.change.after.rule
	some j, d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm in {"aws:kms", "aws:kms:dsse"}
	not known_string(object.get(d, "kms_master_key_id", ""))
	not rc.change.after_unknown.rule[i].apply_server_side_encryption_by_default[j].kms_master_key_id
	msg := sprintf("CMK: %s has no kms_master_key_id (would fall back to AWS managed aws/s3 key)", [rc.address])
}

# ---------------------------------------------------------------- KMS keys
is_custom_key_store(after) if known_string(after.custom_key_store_id)

deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_key"
	not is_custom_key_store(rc.change.after)
	not rc.change.after.enable_key_rotation == true
	msg := sprintf("ROTATION: %s must set enable_key_rotation = true", [rc.address])
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_key"
	rc.change.after.rotation_period_in_days > max_rotation_days
	msg := sprintf("ROTATION: %s rotation_period_in_days > %d", [rc.address, max_rotation_days])
}

# XKS (external key store) keys cannot auto-rotate: demand a manual-rotation runbook tag
deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_key"
	is_custom_key_store(rc.change.after)
	not rc.change.after.tags["rotation-runbook"]
	msg := sprintf("ROTATION: %s is in a custom/external key store; tag rotation-runbook required (no automatic rotation)", [rc.address])
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_key"
	rc.change.after.multi_region == true
	not rc.change.after.tags["residency-approved"] == "true"
	msg := sprintf("RESIDENCY: %s is a multi-Region key; replicas copy key material to other Regions - needs residency-approved tag", [rc.address])
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_kms_replica_key"
	msg := sprintf("RESIDENCY: %s replica key - verify replica Region is in EU allow-list (provider alias check)", [rc.address])
}

# ---------------------------------------------------------------- OpenSearch
deny contains msg if {
	some rc in changes
	rc.type == "aws_opensearch_domain"
	not opensearch_cmk(rc)
	msg := sprintf("CMK: %s must enable encrypt_at_rest with an explicit kms_key_id", [rc.address])
}

opensearch_cmk(rc) if {
	ear := rc.change.after.encrypt_at_rest[0]
	ear.enabled == true
	known_string(ear.kms_key_id)
}

opensearch_cmk(rc) if {
	rc.change.after.encrypt_at_rest[0].enabled == true
	rc.change.after_unknown.encrypt_at_rest[0].kms_key_id == true
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_opensearch_domain"
	not rc.change.after.node_to_node_encryption[0].enabled == true
	msg := sprintf("TRANSIT: %s must enable node_to_node_encryption", [rc.address])
}

# ---------------------------------------------------------------- Bedrock guardrail
deny contains msg if {
	some rc in changes
	rc.type == "aws_bedrock_guardrail"
	count(object.get(rc.change.after, "sensitive_information_policy_config", [])) == 0
	msg := sprintf("DLP: %s must configure sensitive_information_policy_config (PII/regex)", [rc.address])
}

deny contains msg if {
	some rc in changes
	rc.type == "aws_bedrock_guardrail"
	not known_string(object.get(rc.change.after, "kms_key_arn", ""))
	not rc.change.after_unknown.kms_key_arn
	msg := sprintf("CMK: %s should be encrypted with a customer managed key (kms_key_arn)", [rc.address])
}

# ---------------------------------------------------------------- Google CMEK
deny contains msg if {
	some rc in changes
	rc.type == "google_storage_bucket"
	not gcs_cmek(rc)
	msg := sprintf("CMEK: %s must set encryption.default_kms_key_name", [rc.address])
}

gcs_cmek(rc) if known_string(rc.change.after.encryption[0].default_kms_key_name)

gcs_cmek(rc) if rc.change.after_unknown.encryption[0].default_kms_key_name == true

deny contains msg if {
	some rc in changes
	rc.type == "google_kms_crypto_key"
	not known_string(object.get(rc.change.after, "rotation_period", ""))
	not rc.change.after.version_template[0].protection_level == "EXTERNAL"
	msg := sprintf("ROTATION: %s must set rotation_period (Cloud EKM keys excepted - rotate in the external KMS)", [rc.address])
}
