import json
import unittest
from unittest.mock import patch

from api.models.validation import RemediationApplyRequest, RemediationPreviewRequest


class TestRemediationRouter(unittest.IsolatedAsyncioTestCase):
    @patch(
        "api.routers.remediation.preview_virtual_remediation",
        return_value={
            "status": "OK",
            "violation_id": "ISO-A.10-WEAK-HASH",
            "generation": {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 1,
                        "end_line": 1,
                        "original_lines": ["public void foo() { return; }"],
                        "replacement_lines": ["public void foo() { return; }"],
                    }
                ],
                "replacement_method_lines": ["public void foo() { return; }"],
                "replacement_method_code": "public void foo() { return; }",
                "reason": None,
                "raw_response_valid": True,
                "schema_error": None,
            },
        },
    )
    async def test_preview_returns_generation_payload(self, _mock_preview):
        from api.routers.remediation import remediation_preview

        response = await remediation_preview(RemediationPreviewRequest(violation_id="ISO-A.10-WEAK-HASH"))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "OK")
        self.assertEqual(payload["generation"]["decision"], "apply_edits")
        self.assertEqual(payload["generation"]["edits"][0]["start_line"], 1)
        self.assertEqual(payload["generation"]["replacement_method_lines"], ["public void foo() { return; }"])

    @patch(
        "api.routers.remediation.preview_virtual_remediation",
        return_value={
            "status": "NO_FIX",
            "violation_id": "ISO-A.10-WEAK-CRYPTO",
            "error": "NO_FIX: broader protocol context required",
            "generation": {
                "decision": "no_fix",
                "edits": [],
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": "broader protocol context required",
                "raw_response_valid": True,
                "schema_error": None,
            },
        },
    )
    async def test_preview_returns_no_fix_as_success_response(self, _mock_preview):
        from api.routers.remediation import remediation_preview

        response = await remediation_preview(RemediationPreviewRequest(violation_id="ISO-A.10-WEAK-CRYPTO"))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "NO_FIX")
        self.assertEqual(payload["generation"]["decision"], "no_fix")

    @patch(
        "api.routers.remediation.preview_virtual_remediation",
        return_value={
            "status": "GENERATION_ERROR",
            "violation_id": "ISO-A.10-WEAK-HASH",
            "error": "empty_edits",
            "generation": {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "empty_edits",
            },
        },
    )
    async def test_preview_generation_error_returns_500(self, _mock_preview):
        from api.routers.remediation import remediation_preview

        response = await remediation_preview(RemediationPreviewRequest(violation_id="ISO-A.10-WEAK-HASH"))

        self.assertEqual(response.status_code, 500)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "GENERATION_ERROR")

    @patch(
        "api.routers.remediation.apply_remediation",
        return_value={
            "status": "BUILD_ERROR",
            "violation_id": "ISO-A.10-WEAK-HASH",
            "error": "mvn test failed",
            "generation": {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 1,
                        "end_line": 1,
                        "original_lines": ["public void foo() { return; }"],
                        "replacement_lines": ["public void foo() { return; }"],
                    }
                ],
                "replacement_method_lines": ["public void foo() { return; }"],
                "replacement_method_code": "public void foo() { return; }",
                "reason": None,
                "raw_response_valid": True,
                "schema_error": None,
            },
        },
    )
    async def test_apply_build_error_returns_500(self, _mock_apply):
        from api.routers.remediation import remediation_apply

        response = await remediation_apply(RemediationApplyRequest(violation_id="ISO-A.10-WEAK-HASH"))

        self.assertEqual(response.status_code, 500)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "BUILD_ERROR")


if __name__ == "__main__":
    unittest.main()
