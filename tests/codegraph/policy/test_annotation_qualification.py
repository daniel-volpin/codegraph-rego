"""A security annotation must count whether or not it is written qualified.

A remediation that adds ``@org.springframework...PreAuthorize`` secures an
endpoint exactly as ``@PreAuthorize`` does, and Eclipse JDT reports whichever
form the source used. Comparing the written form rejected correct fixes: the
candidate compiled, read correctly, and was still reported by its own policy
gate as not having fixed the violation.
"""

from __future__ import annotations

import shutil
import unittest

import pytest

from tests.codegraph.policy._test_helpers import BundleBuilder, PolicyTestBase

OPA_AVAILABLE = shutil.which("opa") is not None

_ACCESS_RULE = "ISO-A.9.4.1"

_SECURITY_ANNOTATIONS_QUALIFIED_AND_BARE = [
    "@PreAuthorize",
    "@org.springframework.security.access.prepost.PreAuthorize",
    "@Secured",
    "@org.springframework.security.access.annotation.Secured",
    "@RolesAllowed",
    "@javax.annotation.security.RolesAllowed",
    "@DenyAll",
]


def _evaluate(annotations: list[str]) -> set[str]:
    from codegraph.policy.runtime.opa import evaluate_bundle

    bundle = (
        BundleBuilder()
        .with_target_method("com.example.Api.endpoint()")
        .with_file_path("src/main/java/com/example/Api.java")
        .with_source_code('public String endpoint() { return "x"; }')
        .with_annotation(*annotations)
        .build()
    )
    return PolicyTestBase._normalized_violation_ids(evaluate_bundle(bundle))


@unittest.skipUnless(OPA_AVAILABLE, "opa not installed")
class TestAnnotationQualificationParity(unittest.TestCase):
    def test_secured_endpoint_is_not_flagged_in_either_form(self) -> None:
        for annotation in _SECURITY_ANNOTATIONS_QUALIFIED_AND_BARE:
            with self.subTest(annotation=annotation):
                self.assertNotIn(
                    _ACCESS_RULE,
                    _evaluate(["@GetMapping", annotation]),
                    f"{annotation} should satisfy the access-control rule",
                )

    def test_unsecured_endpoint_is_still_flagged(self) -> None:
        """Guards against the qualification fix widening into a blanket pass."""
        for unsecured in (["@GetMapping"], ["@GetMapping", "@Deprecated"], ["@WebServlet", "@Override"]):
            with self.subTest(annotations=unsecured):
                self.assertIn(_ACCESS_RULE, _evaluate(unsecured))

    def test_a_qualified_endpoint_annotation_is_still_recognised(self) -> None:
        """Qualification stripping applies to endpoint detection too, not just security."""
        self.assertIn(_ACCESS_RULE, _evaluate(["@org.springframework.web.bind.annotation.GetMapping"]))


if __name__ == "__main__":
    pytest.main([__file__])
