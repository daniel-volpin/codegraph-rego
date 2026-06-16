from __future__ import annotations

import unittest

from pydantic import ValidationError

from codegraph.remediation.result_models import (
    ArtifactKind,
    Disposition,
    LifecycleReasonCode,
    PatchArtifact,
    ShadowRemediationLifecycle,
    StructuredRepairPlanArtifact,
    TransformationStrategy,
    ValidatorResult,
    ValidatorState,
)


def _base_patch_lifecycle(**overrides: object) -> ShadowRemediationLifecycle:
    payload = {
        "plugin_id": "sql-jdbc-shadow",
        "plugin_version": "1.0.0",
        "supported_rule_id": "ISO-A.8-SQL-INJECTION",
        "language": "java",
        "repair_pattern_id": "SQL-VAL-001",
        "repair_pattern_version": "1.0.0",
        "transformation_strategy": TransformationStrategy.TYPED_STRUCTURED_EDITS,
        "artifact_kind": ArtifactKind.PATCH,
        "disposition": Disposition.REVIEW_REQUIRED,
        "recommended_disposition": Disposition.REVIEW_REQUIRED,
        "pipeline_verified": True,
        "assurance_verified": True,
        "auto_apply_eligible": True,
        "evidence_complete": True,
        "project_policy_dependency_resolved": True,
        "patch_artifact": PatchArtifact(
            target_file="src/main/java/com/example/Foo.java",
            anchor_method="com.example.Foo.find(String)",
            edits=[{"start_line": 10, "end_line": 12, "original_lines": ["a"], "replacement_lines": ["b"]}],
            updated_source_code="public void x() {}",
            diff="@@",
        ),
        "pipeline_checks": [
            ValidatorResult(validator_id="pipeline.anchor", state=ValidatorState.PASS, required=True),
        ],
        "semantic_validators": [
            ValidatorResult(validator_id="sql.placeholder_count", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="sql.binding_order", state=ValidatorState.PASS, required=True),
        ],
        "reproducibility_key": "abc123",
    }
    payload.update(overrides)
    return ShadowRemediationLifecycle.model_validate(payload)


class ShadowLifecycleModelTests(unittest.TestCase):
    def test_enum_serialization(self) -> None:
        lifecycle = _base_patch_lifecycle()
        dumped = lifecycle.model_dump(mode="json")
        self.assertEqual(dumped["artifact_kind"], "patch")
        self.assertEqual(dumped["recommended_disposition"], "review_required")
        self.assertEqual(dumped["semantic_validators"][0]["state"], "PASS")

    def test_patch_artifact_invariant(self) -> None:
        with self.assertRaises(ValidationError):
            _base_patch_lifecycle(artifact_kind=ArtifactKind.PATCH, patch_artifact=None)

    def test_patch_artifact_forbids_other_payloads(self) -> None:
        with self.assertRaises(ValidationError):
            _base_patch_lifecycle(
                structured_repair_plan=StructuredRepairPlanArtifact(summary="manual", steps=["do x"]),
            )

    def test_structured_plan_requires_only_plan_payload(self) -> None:
        lifecycle = ShadowRemediationLifecycle.model_validate(
            {
                "plugin_id": "sql-jdbc-shadow",
                "plugin_version": "1.0.0",
                "supported_rule_id": "ISO-A.8-SQL-INJECTION",
                "language": "java",
                "transformation_strategy": TransformationStrategy.AST_AWARE,
                "artifact_kind": ArtifactKind.STRUCTURED_REPAIR_PLAN,
                "disposition": Disposition.MANUAL_EXECUTION_REQUIRED,
                "recommended_disposition": Disposition.MANUAL_EXECUTION_REQUIRED,
                "evidence_complete": False,
                "project_policy_dependency_resolved": False,
                "structured_repair_plan": {
                    "summary": "Manual review required",
                    "steps": ["Convert Statement to PreparedStatement manually"],
                    "assumptions": ["Connection policy unresolved"],
                },
                "reason_codes": [LifecycleReasonCode.UNRESOLVED_PROJECT_POLICY_DEPENDENCY],
                "semantic_validators": [
                    {"validator_id": "sql.placeholder_count", "state": ValidatorState.UNKNOWN, "required": True}
                ],
                "reproducibility_key": "def456",
            }
        )
        self.assertEqual(lifecycle.artifact_kind, ArtifactKind.STRUCTURED_REPAIR_PLAN)

    def test_none_artifact_forbids_payloads(self) -> None:
        with self.assertRaises(ValidationError):
            ShadowRemediationLifecycle.model_validate(
                {
                    "plugin_id": "sql-jdbc-shadow",
                    "plugin_version": "1.0.0",
                    "supported_rule_id": "ISO-A.8-SQL-INJECTION",
                    "language": "java",
                    "transformation_strategy": TransformationStrategy.AST_AWARE,
                    "artifact_kind": ArtifactKind.NONE,
                    "disposition": Disposition.ABSTAIN,
                    "recommended_disposition": Disposition.ABSTAIN,
                    "patch_artifact": {
                        "target_file": "Foo.java",
                        "anchor_method": "Foo.bar()",
                    },
                    "reproducibility_key": "ghi789",
                }
            )

    def test_auto_apply_disposition_requires_verified_patch(self) -> None:
        with self.assertRaises(ValidationError):
            _base_patch_lifecycle(disposition=Disposition.AUTO_APPLY, assurance_verified=False)

    def test_auto_apply_eligibility_requires_mandatory_pass(self) -> None:
        with self.assertRaises(ValidationError):
            _base_patch_lifecycle(
                semantic_validators=[
                    ValidatorResult(validator_id="sql.placeholder_count", state=ValidatorState.PASS, required=True),
                    ValidatorResult(validator_id="sql.binding_order", state=ValidatorState.UNKNOWN, required=True),
                ]
            )

    def test_assurance_verified_rejects_blocking_reason_code(self) -> None:
        with self.assertRaises(ValidationError):
            _base_patch_lifecycle(reason_codes=[LifecycleReasonCode.SEMANTIC_VERIFICATION_FAILURE])

    def test_reason_code_serialization(self) -> None:
        lifecycle = _base_patch_lifecycle(
            assurance_verified=False,
            auto_apply_eligible=False,
            reason_codes=[LifecycleReasonCode.PIPELINE_VERIFICATION_FAILURE],
        )
        dumped = lifecycle.model_dump(mode="json")
        self.assertEqual(dumped["reason_codes"], ["pipeline_verification_failure"])


if __name__ == "__main__":
    unittest.main()