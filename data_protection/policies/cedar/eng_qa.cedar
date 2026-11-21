// Application-level Cedar policies (evaluated by the orchestrator/PEP inside the
// trusted boundary). Cedar is default-deny; forbid always overrides permit.

// ---- Tools: agents may call read-only tools only -------------------------
@id("agent-read-tools-only")
permit (
  principal is EngQA::Agent,
  action == EngQA::Action::"invokeTool",
  resource is EngQA::Tool
)
when { resource.mode == "read" };

@id("forbid-non-read-tools")
forbid (
  principal is EngQA::Agent,
  action == EngQA::Action::"invokeTool",
  resource is EngQA::Tool
)
unless { resource.mode == "read" };

// ---- Retrieval: ACL + clearance + current revision ------------------------
@id("user-retrieve")
permit (
  principal is EngQA::User,
  action == EngQA::Action::"retrieve",
  resource is EngQA::Document
)
when {
  resource.isCurrent &&
  principal in resource.readers &&
  principal.clearance >= resource.classification
};

// An agent inherits exactly the rights of the user it acts for (no more).
@id("agent-retrieve-on-behalf")
permit (
  principal is EngQA::Agent,
  action == EngQA::Action::"retrieve",
  resource is EngQA::Document
)
when {
  resource.isCurrent &&
  principal.onBehalfOf in resource.readers &&
  principal.onBehalfOf.clearance >= resource.classification
};

// Export-controlled content: requires a matching authorisation (user or delegating user).
@id("export-control-user")
forbid (
  principal is EngQA::User,
  action == EngQA::Action::"retrieve",
  resource is EngQA::Document
)
when { resource.exportControlled }
unless { resource has eccn && principal.exportAuthorised.contains(resource.eccn) };

@id("export-control-agent")
forbid (
  principal is EngQA::Agent,
  action == EngQA::Action::"retrieve",
  resource is EngQA::Document
)
when { resource.exportControlled }
unless {
  resource has eccn &&
  principal.onBehalfOf.exportAuthorised.contains(resource.eccn)
};

// ---- Model egress ("never send to AI") -----------------------------------
@id("send-to-approved-model")
permit (
  principal is EngQA::Agent,
  action == EngQA::Action::"sendToModel",
  resource is EngQA::Document
)
when {
  context.model.inBoundary &&
  context.model.maxClassification >= resource.classification
};

@id("restricted-never-to-model")
forbid (
  principal,
  action == EngQA::Action::"sendToModel",
  resource is EngQA::Document
)
when { resource.classificationLabel == "restricted" };

@id("export-controlled-only-to-approved-in-boundary-model")
forbid (
  principal,
  action == EngQA::Action::"sendToModel",
  resource is EngQA::Document
)
when { resource.exportControlled }
unless { context.model.exportApproved && context.model.inBoundary };

// EU MEMBER-STATE regions only: explicit allow-list, never a prefix match.
// `like "eu-*"` / `like "europe-*"` would admit London (eu-west-2, europe-west2)
// and Zurich (eu-central-2, europe-west6), which are not in the EU.
// Canonical list; keep identical to retrieval_filter.EU_REGIONS and the Rego policies.
@id("model-must-be-eu")
forbid (
  principal,
  action == EngQA::Action::"sendToModel",
  resource
)
unless {
  [
    "eu-central-1", "eu-west-1", "eu-west-3", "eu-south-1", "eu-south-2", "eu-north-1",
    "europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9",
    "europe-southwest1", "europe-north1", "europe-central2"
  ].contains(context.model.region)
};
