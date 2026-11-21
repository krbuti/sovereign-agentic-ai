package main

import rego.v1

provider_eu := {"aws": {"name": "aws", "expressions": {"region": {"constant_value": "eu-central-1"}}}}

provider_us := {"aws": {"name": "aws", "expressions": {"region": {"constant_value": "us-east-1"}}}}

rc(type, after) := {
	"address": sprintf("%s.x", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

plan(prov, rcs) := {"configuration": {"provider_config": prov}, "resource_changes": rcs}

good_kms := rc("aws_kms_key", {"enable_key_rotation": true, "rotation_period_in_days": 180, "multi_region": false})

test_compliant_plan_has_no_denies if {
	count(deny) == 0 with input as plan(provider_eu, [good_kms])
}

test_us_region_denied if {
	some m in deny with input as plan(provider_us, [good_kms])
	startswith(m, "RESIDENCY: provider")
}

# London (UK) and Zurich (CH) are in Europe but not EU member states.
test_london_and_zurich_regions_denied if {
	every r in {"eu-west-2", "eu-central-2"} {
		prov := {"aws": {"name": "aws", "expressions": {"region": {"constant_value": r}}}}
		some m in deny with input as plan(prov, [good_kms])
		startswith(m, "RESIDENCY: provider")
	}
}

test_gcs_london_and_zurich_denied if {
	every loc in {"europe-west2", "europe-west6"} {
		b := rc("google_storage_bucket", {"location": loc, "encryption": [{"default_kms_key_name": "k"}]})
		some m in deny with input as plan({}, [b])
		startswith(m, "RESIDENCY")
	}
}

test_kms_without_rotation_denied if {
	k := rc("aws_kms_key", {"enable_key_rotation": false, "multi_region": false})
	some m in deny with input as plan(provider_eu, [k])
	startswith(m, "ROTATION")
}

test_xks_key_needs_runbook_tag if {
	k := rc("aws_kms_key", {"custom_key_store_id": "cks-123", "multi_region": false, "tags": {}})
	some m in deny with input as plan(provider_eu, [k])
	contains(m, "rotation-runbook")
}

test_xks_key_with_runbook_ok if {
	k := rc("aws_kms_key", {"custom_key_store_id": "cks-123", "multi_region": false, "tags": {"rotation-runbook": "RB-7"}})
	count(deny) == 0 with input as plan(provider_eu, [k])
}

test_multi_region_key_denied if {
	k := rc("aws_kms_key", {"enable_key_rotation": true, "multi_region": true})
	some m in deny with input as plan(provider_eu, [k])
	contains(m, "multi-Region")
}

test_s3_aes256_denied if {
	s := rc("aws_s3_bucket_server_side_encryption_configuration", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256", "kms_master_key_id": ""}]}]})
	some m in deny with input as plan(provider_eu, [s])
	startswith(m, "CMK")
}

test_s3_kms_unknown_key_ok if {
	s := {
		"address": "aws_s3_bucket_server_side_encryption_configuration.docs",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
			"after_unknown": {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}]},
		},
	}
	count(deny) == 0 with input as plan(provider_eu, [s])
}

test_gcs_us_location_and_no_cmek_denied if {
	b := rc("google_storage_bucket", {"location": "US", "encryption": []})
	ds := deny with input as plan({}, [b])
	count(ds) == 2
}

test_gcs_eu_cmek_ok if {
	b := rc("google_storage_bucket", {"location": "EUROPE-WEST3", "encryption": [{"default_kms_key_name": "projects/p/locations/europe-west3/keyRings/r/cryptoKeys/k"}]})
	count(deny) == 0 with input as plan({}, [b])
}

test_ekm_key_exempt_from_rotation_period if {
	k := rc("google_kms_crypto_key", {"version_template": [{"protection_level": "EXTERNAL", "algorithm": "EXTERNAL_SYMMETRIC_ENCRYPTION"}]})
	count(deny) == 0 with input as plan({}, [k])
}

test_guardrail_without_pii_policy_denied if {
	g := rc("aws_bedrock_guardrail", {"kms_key_arn": "arn:aws:kms:eu-central-1:111122223333:key/abc", "sensitive_information_policy_config": []})
	some m in deny with input as plan(provider_eu, [g])
	startswith(m, "DLP")
}

test_guardrail_missing_kms_attr_denied if {
	g := rc("aws_bedrock_guardrail", {"sensitive_information_policy_config": [{"pii_entities_config": []}]})
	some m in deny with input as plan(provider_eu, [g])
	contains(m, "kms_key_arn")
}

test_gcp_key_missing_rotation_attr_denied if {
	k := rc("google_kms_crypto_key", {"version_template": [{"protection_level": "SOFTWARE"}]})
	some m in deny with input as plan({}, [k])
	startswith(m, "ROTATION")
}
