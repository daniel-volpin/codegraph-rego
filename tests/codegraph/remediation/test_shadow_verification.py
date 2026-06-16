from __future__ import annotations

import unittest

from codegraph.remediation.result_models import ValidatorResult, ValidatorState
from codegraph.remediation.verification import BuildRequirement, build_build_validator, pipeline_verified


class ShadowVerificationTests(unittest.TestCase):
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

    def test_required_not_applicable_blocks_pipeline(self) -> None:
        validators = [
            ValidatorResult(validator_id="pipeline.anchor", state=ValidatorState.PASS, required=True),
            ValidatorResult(validator_id="pipeline.build", state=ValidatorState.NOT_APPLICABLE, required=True),
        ]

        self.assertFalse(pipeline_verified(validators))


if __name__ == "__main__":
    unittest.main()