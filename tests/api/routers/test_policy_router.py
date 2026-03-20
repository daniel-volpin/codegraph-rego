import json
import unittest
from unittest.mock import patch

from api.models.validation import PolicyExplainOneRequest


class TestPolicyRouter(unittest.IsolatedAsyncioTestCase):
    @patch(
        "api.routers.policy.generate_policy_explanation_structured",
        return_value={
            "evidence_id": "E1",
            "citation": "src/main/java/org/example/Foo.java lines 10-18",
            "why": "The endpoint is reachable without authorization checks.",
            "fix": "Add a method-level authorization annotation.",
        },
    )
    async def test_policy_explain_one_returns_structured_payload(self, _mock_explain_structured) -> None:
        from api.routers.policy import policy_explain_one

        response = await policy_explain_one(
            PolicyExplainOneRequest(
                violation={"violation_id": "ISO-A.9.4.1", "evidence": {}},
                include_graph_context=True,
                model="dummy-model",
            )
        )

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "OK")
        self.assertEqual(
            payload["explanation_structured"],
            {
                "evidence_id": "E1",
                "citation": "src/main/java/org/example/Foo.java lines 10-18",
                "why": "The endpoint is reachable without authorization checks.",
                "fix": "Add a method-level authorization annotation.",
            },
        )
        self.assertEqual(
            payload["explanation"],
            "Citation: src/main/java/org/example/Foo.java lines 10-18\n"
            "Why: The endpoint is reachable without authorization checks.\n"
            "Fix: Add a method-level authorization annotation.",
        )


if __name__ == "__main__":
    unittest.main()
