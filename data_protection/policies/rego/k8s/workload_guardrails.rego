# Kubernetes guardrails for agent / retrieval / DLP workloads (EKS or GKE).
# Usable as: conftest test --policy policies/rego/k8s deployment.yaml   (shift-left)
# For live admission use the same logic in Gatekeeper ConstraintTemplates or
# OPA-Envoy/kube-mgmt; there `input` is wrapped as input.request.object.
package main

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job"}

# Registries only in EU MEMBER-STATE regions (canonical list, same as
# terraform/residency_cmk.rego). Enumerated, not wildcarded: a prefix such as
# eu-(central|west)-N or europe-* would also admit London (eu-west-2 /
# europe-west2) and Zurich (eu-central-2 / europe-west6), which are not EU.
eu_registry_patterns := [
	`^[0-9]{12}\.dkr\.ecr\.(eu-central-1|eu-west-1|eu-west-3|eu-south-1|eu-south-2|eu-north-1)\.amazonaws\.com/`,
	`^(europe-west1|europe-west3|europe-west4|europe-west8|europe-west9|europe-southwest1|europe-north1|europe-central2)-docker\.pkg\.dev/`,
]

eu_node_regions := {"eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "europe-west3", "europe-west4", "europe-west1"}

obj := input.request.object if input.request.object

else := input

pod_spec := obj.spec if obj.kind == "Pod"

pod_spec := obj.spec.template.spec if obj.kind in workload_kinds

labels := object.get(obj.metadata, "labels", {})

containers contains c if {
	some c in pod_spec.containers
}

containers contains c if {
	some c in object.get(pod_spec, "initContainers", [])
}

# 1. every workload carries the classification of the data it processes
deny contains msg if {
	pod_spec
	not object.get(labels, "data-classification", "") in {"public", "internal", "confidential", "restricted"}
	msg := sprintf("%s/%s: label data-classification must be one of public|internal|confidential|restricted", [obj.kind, obj.metadata.name])
}

# 2. images only from EU registries, pinned by digest
deny contains msg if {
	some c in containers
	not eu_registry(c.image)
	msg := sprintf("container %q: image %q not from an EU member-state registry (allow-listed ECR / Artifact Registry regions)", [c.name, c.image])
}

deny contains msg if {
	some c in containers
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q: image must be pinned by digest", [c.name])
}

eu_registry(img) if {
	some p in eu_registry_patterns
	regex.match(p, img)
}

# 3. no literal secrets in env (use valueFrom secretKeyRef / CSI driver backed by KMS)
deny contains msg if {
	some c in containers
	some e in object.get(c, "env", [])
	regex.match(`(?i)(secret|password|passwd|token|api_?key|private_?key)`, e.name)
	e.value
	msg := sprintf("container %q: env %q has a literal value; use secretKeyRef", [c.name, e.name])
}

# 4. confidential/restricted workloads must be pinned to EU nodes
deny contains msg if {
	labels["data-classification"] in {"confidential", "restricted"}
	region := object.get(object.get(pod_spec, "nodeSelector", {}), "topology.kubernetes.io/region", "")
	not region in eu_node_regions
	msg := sprintf("%s/%s: %s workloads need nodeSelector topology.kubernetes.io/region in EU", [obj.kind, obj.metadata.name, labels["data-classification"]])
}

# 5. restricted workloads may not reach model endpoints (enforced via NetworkPolicy; label is the contract)
deny contains msg if {
	labels["data-classification"] == "restricted"
	not object.get(labels, "model-egress", "") == "none"
	msg := sprintf("%s/%s: restricted workloads must carry model-egress=none (never send restricted data to a model)", [obj.kind, obj.metadata.name])
}
