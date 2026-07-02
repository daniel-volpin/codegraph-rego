import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.models.validation import RemediationApplyRequest, RemediationPreviewRequest


def _build_app() -> FastAPI:
    from api.routers.remediation import router as remediation_router

    app = FastAPI()
    app.include_router(remediation_router)
    return app


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


class TestRemediationApplyRequestValidation(unittest.TestCase):
    """Request-contract guard: invalid mode/max_attempts must 422 at the
    framework boundary without ever invoking the remediation service."""

    _OK_RESULT = {"status": "OK", "violation_id": "ISO-A.10-WEAK-HASH"}

    def _post_apply(self, mock_apply, payload: dict):
        mock_apply.return_value = dict(self._OK_RESULT)
        client = TestClient(_build_app())
        return client.post("/remediation/apply", json={"violation_id": "ISO-A.10-WEAK-HASH", **payload})

    @patch("api.routers.remediation.apply_remediation")
    def test_defaults_are_dry_run_with_two_attempts(self, mock_apply):
        response = self._post_apply(mock_apply, {})

        self.assertEqual(response.status_code, 200)
        _, kwargs = mock_apply.call_args
        self.assertEqual(kwargs["mode"], "dry_run")
        self.assertEqual(kwargs["max_attempts"], 2)

    @patch("api.routers.remediation.apply_remediation")
    def test_dry_run_mode_is_accepted(self, mock_apply):
        response = self._post_apply(mock_apply, {"mode": "dry_run"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_apply.call_args.kwargs["mode"], "dry_run")

    @patch("api.routers.remediation.apply_remediation")
    def test_apply_mode_is_accepted(self, mock_apply):
        response = self._post_apply(mock_apply, {"mode": "apply"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_apply.call_args.kwargs["mode"], "apply")

    @patch("api.routers.remediation.apply_remediation")
    def test_unknown_mode_is_rejected_without_invoking_service(self, mock_apply):
        response = self._post_apply(mock_apply, {"mode": "preview"})

        self.assertEqual(response.status_code, 422)
        mock_apply.assert_not_called()

    @patch("api.routers.remediation.apply_remediation")
    def test_miscapitalized_mode_is_rejected_without_invoking_service(self, mock_apply):
        response = self._post_apply(mock_apply, {"mode": "Apply"})

        self.assertEqual(response.status_code, 422)
        mock_apply.assert_not_called()

    @patch("api.routers.remediation.apply_remediation")
    def test_max_attempts_zero_is_rejected_without_invoking_service(self, mock_apply):
        response = self._post_apply(mock_apply, {"max_attempts": 0})

        self.assertEqual(response.status_code, 422)
        mock_apply.assert_not_called()

    @patch("api.routers.remediation.apply_remediation")
    def test_max_attempts_above_cap_is_rejected_without_invoking_service(self, mock_apply):
        response = self._post_apply(mock_apply, {"max_attempts": 6})

        self.assertEqual(response.status_code, 422)
        mock_apply.assert_not_called()

    @patch("api.routers.remediation.apply_remediation")
    def test_max_attempts_lower_bound_is_accepted(self, mock_apply):
        response = self._post_apply(mock_apply, {"max_attempts": 1})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_apply.call_args.kwargs["max_attempts"], 1)

    @patch("api.routers.remediation.apply_remediation")
    def test_max_attempts_upper_bound_is_accepted(self, mock_apply):
        response = self._post_apply(mock_apply, {"max_attempts": 5})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_apply.call_args.kwargs["max_attempts"], 5)


if __name__ == "__main__":
    unittest.main()
