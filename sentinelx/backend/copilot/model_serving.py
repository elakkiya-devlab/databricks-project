import os

PROMPT = ("Classify the user's question about credential governance into exactly one of these intents: {intents}. "
          "Reply with the intent name only, or 'none'. Do not answer the question.")


class ModelServingIntentProvider:
    """Optional Databricks Model Serving intent classifier.

    Only the user's question text is sent, and only an allowlisted intent name is accepted back. The model never
    receives governance data, never generates facts, and cannot call remediation APIs.
    """

    def __init__(self, endpoint, client=None):
        self.endpoint = endpoint
        self._client = client

    @classmethod
    def from_env(cls, environ=None):
        endpoint = (os.environ if environ is None else environ).get("SENTINELX_MODEL_SERVING_ENDPOINT", "").strip()
        return cls(endpoint) if endpoint else None

    def classify(self, question, allowed_intents):
        try:
            client = self._client
            if client is None:
                from databricks.sdk import WorkspaceClient
                client = self._client = WorkspaceClient()
            from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
            response = client.serving_endpoints.query(
                name=self.endpoint, max_tokens=12, temperature=0,
                messages=[ChatMessage(role=ChatMessageRole.SYSTEM, content=PROMPT.format(intents=", ".join(allowed_intents))),
                          ChatMessage(role=ChatMessageRole.USER, content=question[:500])])
            answer = response.choices[0].message.content.strip().lower()
        except Exception:
            return None
        return answer if answer in allowed_intents else None
