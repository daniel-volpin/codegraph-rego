from __future__ import annotations

import unittest

from codegraph.remediation.plugin_types import RepairPatternContract
from codegraph.remediation.result_models import TransformationStrategy, ValidatorResult, ValidatorState
from codegraph.remediation.shadow import _enforce_declared_mandatory_semantic_validators
from codegraph.remediation.verification import BuildRequirement, build_build_validator, pipeline_verified


class ShadowVerificationTests(unittest.TestCase):
    def _pattern(self, mandatory_ids: list[str]) -> RepairPatternContract:
        return RepairPatternContract(
            pattern_id="TEST",
            pattern_version="1.0.0",
            transformation_strategy=TransformationStrategy.TYPED_STRUCTURED_EDITS,
            max_edit_scope_lines=1,
            mandatory_semantic_validators=mandatory_ids,
            auto_apply_capable=False,
        )

    def test_build_skipped_when_mandatory_is_unknown(self) -> None:
        validator = build_build_validator(
            build_requirement=BuildRequirement.ALWAYS,
            build_root=None,
            compilation={"attempted": False, "success": False, "skipped_reason": "No build system detected"},
        )

        self.assertEqual(validator.state, ValidatorState.UNKNOWN)
        self.assertTrue(validator.required)

    def test_optional_not_applicable_validator_does_not_fail_pipeline(self) -> None:
        validators = [
            ValidatorResult(validator_id="pipeline.anchor", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="pipeline.build", state=ValidatorState.NOT_APPLICABLE, required=False),
        ]

        self.assertTrue(pipeline_verified(validators))

    def test_required_unknown_blocks_pipeline(self) -> None:
        validators = [
            ValidatorResult(validator_id="pipeline.anchor", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="pipeline.build", state=ValidatorState.UNKNOWN, required=True),
        ]

        self.assertFalse(pipeline_verified(validators))

    def test_declared_mandatory_validator_missing_is_blocking(self) -> None:
        validators = [
            ValidatorResult(validator_id="sql.a", state=ValidatorState.PASS, required=True),
        ]

        enforced, contract_ok = _enforce_declared_mandatory_semantic_validators(
            self._pattern(["sql.a", "sql.b"]),
            validators,
        )

        self.assertFalse(contract_ok)
        self.assertTrue(any(validator.validator_id == "semantic.contract.missing:sql.b" for validator in enforced))

    def test_duplicate_declared_validator_ids_are_blocking(self) -> None:
        validators = [
            ValidatorResult(validator_id="sql.a", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="sql.a", state=ValidatorState.PASS, required=True),
        ]

        enforced, contract_ok = _enforce_declared_mandatory_semantic_validators(
            self._pattern(["sql.a"]),
            validators,
        )

        self.assertFalse(contract_ok)
        self.assertTrue(any(validator.validator_id == "semantic.contract.duplicate:sql.a" for validator in enforced))

    def test_complete_declared_validator_set_can_pass(self) -> None:
        validators = [
            ValidatorResult(validator_id="sql.a", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="sql.b", state=ValidatorState.PASS, required=True),
        ]

        enforced, contract_ok = _enforce_declared_mandatory_semantic_validators(
            self._pattern(["sql.a", "sql.b"]),
            validators,
        )

        self.assertTrue(contract_ok)
        self.assertEqual(enforced, validators)

    def test_extra_optional_validator_does_not_substitute_for_missing_mandatory(self) -> None:
        validators = [
            ValidatorResult(validator_id="sql.a", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="sql.extra", state=ValidatorState.FAIL, required=False),
        ]

        enforced, contract_ok = _enforce_declared_mandatory_semantic_validators(
            self._pattern(["sql.a"]),
            validators,
        )

        self.assertTrue(contract_ok)
        self.assertEqual(len(enforced), 2)

    def test_empty_emitted_validator_set_is_blocking(self) -> None:
        enforced, contract_ok = _enforce_declared_mandatory_semantic_validators(
            self._pattern(["sql.a"]),
            [],
        )

        self.assertFalse(contract_ok)
        self.assertTrue(any(validator.validator_id == "semantic.contract.missing:sql.a" for validator in enforced))

    def test_required_not_applicable_blocks_pipeline(self) -> None:
        validators = [
            ValidatorResult(validator_id="pipeline.anchor", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="pipeline.build", state=ValidatorState.NOT_APPLICABLE, required=True),
        ]

        self.assertFalse(pipeline_verified(validators))


if __name__ == "__main__":
    unittest.main()