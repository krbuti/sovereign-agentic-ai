// Amazon Bedrock AgentCore Policy (Cedar) for the AgentCore Gateway.
// Syntax follows the AgentCore developer guide ("Guardrails in policies"):
//   action   == AgentCore::Action::"<TargetName>___<ToolName>"  (MCP targets)
//   resource == AgentCore::Gateway::"<gateway-arn>"             (must be specific)
// Gateway is default-deny: only the permitted (read) tools are callable.
// Guardrails-in-policy regions in Europe at time of writing: London, Stockholm
// -> Stockholm (eu-north-1) used here because it is inside the EU.

// ---- read-only tools ------------------------------------------------------
permit (
  principal,
  action == AgentCore::Action::"KnowledgeSearch___search_documents",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
);

permit (
  principal,
  action == AgentCore::Action::"IncidentDb___get_incident",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
);

// Belt and braces: an explicit forbid on the write tool survives a future
// over-broad permit (forbid overrides permit).
forbid (
  principal,
  action == AgentCore::Action::"IncidentDb___update_incident",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
);

// ---- inference target: block prompt injection on input --------------------
forbid (
  principal,
  action == AgentCore::Action::"ByomLlm___POST:/v1/chat/completions",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
) when guardrails {
  BedrockGuardrails::PromptAttack(["PROMPT_INJECTION", "JAILBREAK"], ["$.messages[*].content"]).maxConfidenceScore().greaterThan(decimal("0.6"))
};

permit (
  principal,
  action == AgentCore::Action::"ByomLlm___POST:/v1/chat/completions",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
);

// ---- output: suppress responses that carry credentials or PII ------------
suppressOutput (
  principal,
  action == AgentCore::Action::"ByomLlm___POST:/v1/chat/completions",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-north-1:111122223333:gateway/eng-qa-gw"
) when guardrails {
  BedrockGuardrails::SensitiveInformation(["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD", "EMAIL", "PHONE"], ["$.choices[*].message.content"]).count() > 0
};

// NOTE: Guardrails here are ML-scored (no regex). Confidential-IP detection is
// NOT possible with these categories; that is handled upstream by
// classification-aware retrieval + eng_qa.cedar "restricted-never-to-model".
