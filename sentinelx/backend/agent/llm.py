"""Optional Databricks Model Serving language layer for the SentinelPilot agent.

The model is used for two things only: (1) turning a free-form message into one allowlisted tool name plus an optional
target string, and (2) writing a short plain-language note about facts the backend already established. It never receives
credentials, secret values or AWS/Databricks tokens, never executes anything, and its notes are rejected if they contradict
the verified outcome, so execution stays deterministic.
"""

import json
import os
import re

TOOLS = ("aws_status", "list_secrets", "plan_rotation", "explain_finding", "ask_governance", "help")
TARGET = re.compile(r"^[\w/+=.@:-]{2,200}$")
SECRET_LIKE = re.compile(r"(dapi[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{12,}|[A-Za-z0-9+/_=-]{32,})")
SUCCESS_WORDS = re.compile(r"\b(success(?:ful|fully)?|succeeded|completed|done|rotated|updated)\b", re.I)

INTERPRET_PROMPT = (
    "You route messages for a credential-governance assistant. Choose exactly one tool from: {tools}. "
    "Use plan_rotation only when the user wants a secret or credential rotated, renewed or fixed; put the secret name, "
    "ARN, finding ID (SX-####) or a short descriptive name in target. Use explain_finding for questions about a specific "
    "finding ID, ask_governance for other questions about governance data, aws_status for connectivity, list_secrets for "
    "inventory, and help otherwise. Reply with JSON only: {{\"tool\": \"...\", \"target\": \"...\" or null}}.")
NARRATE_PROMPT = (
    "You are SentinelPilot, a careful credential-governance assistant. Using ONLY the JSON facts, write at most three short "
    "plain sentences for an operator: what it means and the sensible next step. Never claim anything was changed or "
    "succeeded unless facts.outcome is 'succeeded'. Never include identifiers that look like keys or tokens. No markdown.")


class AgentLanguageModel:
    def __init__(self, endpoint, client=None):
        self.endpoint, self._client = endpoint, client

    @classmethod
    def from_env(cls, environ=None, client=None):
        endpoint = (os.environ if environ is None else environ).get("SENTINELX_MODEL_SERVING_ENDPOINT", "").strip()
        return cls(endpoint, client) if endpoint else None

    def _chat(self, system, user, max_tokens):
        client = self._client
        if client is None:
            from databricks.sdk import WorkspaceClient
            client = self._client = WorkspaceClient()
        from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
        response = client.serving_endpoints.query(
            name=self.endpoint, max_tokens=max_tokens, temperature=0,
            messages=[ChatMessage(role=ChatMessageRole.SYSTEM, content=system), ChatMessage(role=ChatMessageRole.USER, content=user)])
        return (response.choices[0].message.content or "").strip()

    def interpret(self, message):
        """Return {'tool', 'target'} or None. Only allowlisted tools and well-formed targets are accepted."""
        try:
            raw = self._chat(INTERPRET_PROMPT.format(tools=", ".join(TOOLS)), message[:500], 60)
            data = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        except Exception:  # noqa: BLE001 - any model or parsing failure falls back to the deterministic help path
            return None
        tool, target = data.get("tool"), data.get("target")
        if tool not in TOOLS:
            return None
        if target is not None and not (isinstance(target, str) and TARGET.match(target.strip())):
            target = None
        return dict(tool=tool, target=target.strip() if target else None)

    def narrate(self, facts):
        """Return a short note consistent with the backend's facts, or None."""
        try:
            text = self._chat(NARRATE_PROMPT, json.dumps(facts, default=str)[:2000], 160)
        except Exception:  # noqa: BLE001
            return None
        text = " ".join(text.split())[:600]
        if not text or SECRET_LIKE.search(text):
            return None
        if facts.get("outcome") != "succeeded" and SUCCESS_WORDS.search(text):
            return None
        return text
