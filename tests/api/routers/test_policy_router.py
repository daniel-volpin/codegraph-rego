import json
import unittest
from unittest.mock import patch

from api.models.validation import PolicyEvaluateWithLLMRequest, PolicyExplainOneRequest


class TestPolicyRouter(unittest.IsolatedAsyncioTestCase):
    async def test_all_failed_scan_returns_error_status(self):
        from api.routers.policy import policy_evaluate

        result = {"violations": [], "error": "All bundles failed", "evaluation": {"status": "failed"}}
        with patch("api.routers.policy.evaluate_policies", return_value=result):
            response = await policy_evaluate()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.body), result)

    async def test_explanation_scan_retains_completeness_and_unexplained_findings(self):
        from api.routers.policy import policy_evaluate_with_llm

        result = {
            "violations": [{"violation_id": "A"}, {"violation_id": "B"}],
            "evaluation": {"status": "partial", "failed_bundles": 1},
            "failed_bundles": [{"target_method": "broken"}],
        }
        with (
            patch("api.routers.policy.evaluate_policies", return_value=result),
            patch("api.routers.policy.explain_policy_violations", return_value=[{"explanation": "one"}]),
        ):
            response = await policy_evaluate_with_llm(PolicyEvaluateWithLLMRequest(limit=1))
        payload = json.loads(response.body)
        self.assertEqual(payload["evaluation"], result["evaluation"])
        self.assertEqual(payload["violations"], result["violations"])
        self.assertEqual(payload["failed_bundles"], result["failed_bundles"])
        self.assertEqual(payload["enriched"], [{"explanation": "one"}])

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

    @patch("api.routers.policy.generate_policy_explanation", return_value="Fallback plain explanation")
    @patch(
        "api.routers.policy.generate_policy_explanation_structured",
        side_effect=ValueError("invalid structured explanation payload"),
    )
    async def test_policy_explain_one_falls_back_to_plain_explanation(
        self,
        _mock_explain_structured,
        _mock_explain_plain,
    ) -> None:
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
        self.assertIsNone(payload["explanation_structured"])
        self.assertEqual(payload["explanation"], "Fallback plain explanation")


if __name__ == "__main__":
    unittest.main()
