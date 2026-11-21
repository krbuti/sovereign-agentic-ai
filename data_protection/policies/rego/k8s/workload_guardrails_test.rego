package main

import rego.v1

good := {
	"kind": "Deployment",
	"metadata": {"name": "retriever", "labels": {"data-classification": "confidential"}},
	"spec": {"template": {"spec": {
		"nodeSelector": {"topology.kubernetes.io/region": "eu-central-1"},
		"containers": [{
			"name": "app",
			"image": "111122223333.dkr.ecr.eu-central-1.amazonaws.com/retriever@sha256:abc123",
			"env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}],
		}],
	}}},
}

test_good_deployment if {
	count(deny) == 0 with input as good
}

test_good_as_admission_review if {
	count(deny) == 0 with input as {"request": {"object": good}}
}

test_us_registry_and_tag_denied if {
	bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "docker.io/library/app:latest"}])
	count(deny) == 2 with input as bad
}

test_literal_secret_denied if {
	bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/env/0", "value": {"name": "API_KEY", "value": "abc"}}])
	some m in deny with input as bad
	contains(m, "literal value")
}

test_restricted_needs_eu_nodes_and_no_model_egress if {
	bad := json.patch(good, [
		{"op": "replace", "path": "/metadata/labels/data-classification", "value": "restricted"},
		{"op": "remove", "path": "/spec/template/spec/nodeSelector"},
	])
	count(deny) == 2 with input as bad
}

test_missing_classification if {
	bad := json.patch(good, [{"op": "remove", "path": "/metadata/labels/data-classification"}])
	count(deny) == 1 with input as bad
}

# London (UK) and Zurich (CH) registries are in Europe but not EU member states.
test_london_and_zurich_registries_denied if {
	every img in {
		"111122223333.dkr.ecr.eu-west-2.amazonaws.com/retriever@sha256:abc123",
		"111122223333.dkr.ecr.eu-central-2.amazonaws.com/retriever@sha256:abc123",
		"europe-west2-docker.pkg.dev/p/r/retriever@sha256:abc123",
		"europe-west6-docker.pkg.dev/p/r/retriever@sha256:abc123",
	} {
		bad := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": img}])
		some m in deny with input as bad
		contains(m, "not from an EU member-state registry")
	}
}

test_eu_artifact_registry_allowed if {
	ok := json.patch(good, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "europe-west3-docker.pkg.dev/p/r/retriever@sha256:abc123"}])
	count(deny) == 0 with input as ok
}
