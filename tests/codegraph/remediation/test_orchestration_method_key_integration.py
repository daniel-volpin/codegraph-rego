from __future__ import annotations

import json
import tempfile as stdlib_tempfile
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Any
from unittest.mock import patch

import pytest

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation.candidate import build_candidate_overlay
from codegraph.remediation.context import clear_policy_evaluation_cache
from codegraph.remediation.orchestration import _get_service, apply_remediation, preview_virtual_remediation
from codegraph.remediation.scoped_verification import CapturedPolicyInputs, PolicyFingerprint

RULE_ID = "ISO-A.10-WEAK-HASH"
REAL_TEMPORARY_DIRECTORY = stdlib_tempfile.TemporaryDirectory


def _source_fixture(tmp_path: Path, *, newline: str = "\n") -> dict[str, Any]:
    root = tmp_path / "workspace"
    rel = Path("src/main/java/demo/Example.java")
    source_path = root / rel
    source_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "package demo;",
        "class Example {",
        "  void hash() throws Exception {",
        '    java.security.MessageDigest.getInstance("MD5");',
        "  }",
        "}",
        "",
    ]
    original = newline.join(lines)
    source_path.write_text(original, encoding="utf-8", newline="")
    original_bytes = source_path.read_bytes()
    snapshot = create_source_snapshot_from_bytes(
        workspace_root=root,
        source_path=source_path,
        source_bytes=original_bytes,
        method_selector="demo.Example#hash()",
        expected_source_sha256=sha256_hex(original_bytes),
    )
    method_key = f"workspace@revision:{rel.as_posix()}#{snapshot.identity.source_key}"
    replacement_method = (
        "void hash() throws Exception {\n"
        '    java.security.MessageDigest.getInstance("SHA-256");\n'
        "  }"
    )
    overlay = build_candidate_overlay(snapshot, replacement_method.encode("utf-8"))
    return {
        "root": root,
        "rel": rel,
        "source_path": source_path,
        "original": original,
        "original_bytes": original_bytes,
        "snapshot": snapshot,
        "method_key": method_key,
        "replacement_method": replacement_method,
        "overlay": overlay,
    }


def _policy_result(fixture: dict[str, Any]) -> dict[str, Any]:
    source_path = fixture["source_path"]
    source = fixture["snapshot"].method_source
    return {
        "violations": [
            {
                "violation_id": RULE_ID,
                "method_key": "workspace@revision:wrong.java#method:hash/0",
                "target_method": "demo.Example.hash()",
                "file_path": source_path.as_posix(),
                "evidence": {
                    "source_code": "stale",
                    "source_code_raw": "stale",
                    "parser": {"source_sha256": fixture["snapshot"].file_sha256},
                    "source_sha256": fixture["snapshot"].file_sha256,
                },
            },
            {
                "violation_id": RULE_ID,
                "method_key": fixture["method_key"],
                "target_method": "demo.Example.hash()",
                "file_path": source_path.as_posix(),
                "evidence": {
                    "source_code": source,
                    "source_code_raw": source,
                    "parser": {"source_sha256": fixture["snapshot"].file_sha256},
                    "source_sha256": fixture["snapshot"].file_sha256,
                    "graph_context": {},
                    "vector_context": [],
                },
            },
        ]
    }


def _llm_response(fixture: dict[str, Any]) -> str:
    return json.dumps(
        {
            "decision": "apply_edits",
            "edits": [
                {
                    "start_line": 1,
                    "end_line": len(fixture["snapshot"].method_source.splitlines()),
                    "original_lines": fixture["snapshot"].method_source.splitlines(),
                    "replacement_lines": fixture["replacement_method"].splitlines(),
                }
            ],
            "reason": "replace weak digest",
        }
    )


def _policy_capture(capture_root: Path) -> CapturedPolicyInputs:
    policy_dir = capture_root / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "catalog.json").write_text('{"controls":[{"id":"ISO-A.10-WEAK-HASH"}]}', encoding="utf-8")
    return CapturedPolicyInputs(
        source_dir=policy_dir,
        fingerprint=PolicyFingerprint(
            policy_sha256="policy-sha",
            engine_name="opa",
            engine_version="test",
            files=("catalog.json",),
        ),
    )


def _patch_public_boundaries(fixture: dict[str, Any], *, build_result: dict[str, Any] | None = None):
    _get_service.cache_clear()
    clear_policy_evaluation_cache()
    build_result = build_result or {"attempted": True, "success": True, "output_snippet": ""}
    return (
        patch(
            "codegraph.remediation.service.PolicyEvaluator",
            return_value=SimpleNamespace(evaluate=lambda _method: {"violations": [{"violation_id": RULE_ID}]}),
        ),
        patch("codegraph.remediation.service.evaluate_policies", return_value=_policy_result(fixture)),
        patch("codegraph.remediation.service.load_policy_catalog", return_value={RULE_ID: {"title": "Weak hash"}}),
        patch("codegraph.llm.client._DEFAULT_TRANSPORT.generate", side_effect=lambda *_a, **_k: _llm_response(fixture)),
        patch("codegraph.remediation.scoped_verification._copy_and_fingerprint_policy", side_effect=lambda _p, root: _policy_capture(root)),
        patch("codegraph.remediation.scoped_verification.opa_runtime.evaluate_bundle", side_effect=[[{"violation_id": RULE_ID}], []]),
        patch("codegraph.remediation.service.RemediationService._compile_project", return_value=build_result),
    )


def test_public_preview_uses_required_method_key_and_leaves_source_untouched(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path)
    patches = _patch_public_boundaries(fixture)
    try:
        for active in patches:
            active.start()
        result = preview_virtual_remediation(
            RULE_ID,
            method_key=fixture["method_key"],
            file_path=fixture["source_path"].as_posix(),
        )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result.get("error") is None
    assert result["status"] == "OK", result
    assert result["method_key"] == fixture["method_key"]
    assert "SHA-256" in result["updated_source_code"]
    assert fixture["source_path"].read_bytes() == fixture["original_bytes"]


def test_public_dry_run_verifies_actual_candidate_without_source_or_graph_write(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path)
    patches = _patch_public_boundaries(fixture)
    captured: dict[str, Any] = {}

    def capture_evaluate(bundle: dict[str, Any], **_kwargs: Any):
        captured.setdefault("bundles", []).append(bundle)
        return [{"violation_id": RULE_ID}] if len(captured["bundles"]) == 1 else []

    try:
        for active in patches:
            active.start()
        with (
            patch("codegraph.remediation.scoped_verification.opa_runtime.evaluate_bundle", side_effect=capture_evaluate),
            patch("codegraph.remediation.apply_flow.ingest", side_effect=AssertionError("dry run must not publish")),
        ):
            result = apply_remediation(
                RULE_ID,
                method_key=fixture["method_key"],
                file_path=fixture["source_path"].as_posix(),
                mode="dry_run",
                max_attempts=1,
            )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result["status"] == "OK", result
    assert result["method_key"] == fixture["method_key"]
    assert fixture["source_path"].read_bytes() == fixture["original_bytes"]
    assert captured["bundles"][1]["file_sha256"] == fixture["overlay"].candidate_file_sha256


def test_public_apply_writes_exact_compiled_and_verified_candidate_bytes(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path, newline="\r\n")
    compiled: dict[str, bytes] = {}

    def compile_project(build_root: Path, **_kwargs: Any) -> dict[str, Any]:
        candidate = next(Path(build_root).rglob("Example.java"))
        compiled["bytes"] = candidate.read_bytes()
        return {"attempted": True, "success": True, "output_snippet": ""}

    patches = _patch_public_boundaries(fixture)
    try:
        for active in patches:
            active.start()
        with (
            patch("codegraph.remediation.service.RemediationService._compile_project", side_effect=compile_project),
            patch(
                "codegraph.remediation.service.RemediationService._prepare_temp_workspace",
                side_effect=lambda _self, tmp_root, _source: (
                    tmp_root,
                    Path(tmp_root) / "src/main/java/demo/Example.java",
                    tmp_root,
                ),
                autospec=True,
            ),
            patch("codegraph.remediation.apply_flow.ingest", return_value=object()),
            patch("codegraph.remediation.apply_flow._build_search_embeddings"),
        ):
            result = apply_remediation(
                RULE_ID,
                method_key=fixture["method_key"],
                file_path=fixture["source_path"].as_posix(),
                mode="apply",
                max_attempts=1,
            )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result.get("error") is None
    assert result["status"] == "OK", result
    assert compiled["bytes"] == fixture["overlay"].candidate_file_bytes
    assert fixture["source_path"].read_bytes() == fixture["overlay"].candidate_file_bytes


@pytest.mark.parametrize("build_result", [{"attempted": False, "success": False}, {"attempted": True, "success": False}])
def test_public_apply_refuses_non_pass_or_skipped_build(tmp_path: Path, build_result: dict[str, Any]) -> None:
    fixture = _source_fixture(tmp_path)
    patches = _patch_public_boundaries(fixture, build_result=build_result)
    try:
        for active in patches:
            active.start()
        with patch("codegraph.remediation.apply_flow.ingest", side_effect=AssertionError("must not publish")):
            result = apply_remediation(
                RULE_ID,
                method_key=fixture["method_key"],
                file_path=fixture["source_path"].as_posix(),
                mode="apply",
                max_attempts=1,
            )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result["status"] in {"VERIFICATION_ERROR", "BUILD_ERROR"}
    assert fixture["source_path"].read_bytes() == fixture["original_bytes"]


def test_public_apply_stale_original_blocks_write_after_verification(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path)

    def compile_and_race(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        fixture["source_path"].write_text(fixture["original"].replace("MD5", "SHA-1"), encoding="utf-8")
        return {"attempted": True, "success": True, "output_snippet": ""}

    patches = _patch_public_boundaries(fixture)
    try:
        for active in patches:
            active.start()
        with (
            patch("codegraph.remediation.service.RemediationService._compile_project", side_effect=compile_and_race),
            patch("codegraph.remediation.apply_flow.ingest", side_effect=AssertionError("stale source must not publish")),
        ):
            result = apply_remediation(
                RULE_ID,
                method_key=fixture["method_key"],
                file_path=fixture["source_path"].as_posix(),
                mode="apply",
                max_attempts=1,
            )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result["status"] == "VERIFICATION_ERROR"
    assert result["verification"]["status"] == "STALE_CANDIDATE"
    assert b"SHA-1" in fixture["source_path"].read_bytes()


def test_cleanup_failure_before_publication_leaves_source_and_graph_untouched(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path)
    patches = _patch_public_boundaries(fixture)

    class FailingCleanupTemporaryDirectory:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._inner = REAL_TEMPORARY_DIRECTORY(*args, **kwargs)

        def __enter__(self) -> str:
            return self._inner.__enter__()

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: TracebackType | None,
        ) -> None:
            self._inner.__exit__(exc_type, exc, tb)
            raise OSError("cleanup failed")

    try:
        for active in patches:
            active.start()
        with (
            patch("codegraph.remediation.apply_flow.tempfile.TemporaryDirectory", FailingCleanupTemporaryDirectory),
            patch("codegraph.remediation.apply_flow.ingest", side_effect=AssertionError("cleanup failure must not publish")),
        ):
            result = apply_remediation(
                RULE_ID,
                method_key=fixture["method_key"],
                file_path=fixture["source_path"].as_posix(),
                mode="apply",
                max_attempts=1,
            )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert result["status"] == "VERIFICATION_ERROR"
    assert "cleanup failed" in result["error"]
    assert fixture["source_path"].read_bytes() == fixture["original_bytes"]


def test_public_remediation_rejects_missing_and_stale_method_key_without_signature_fallback(tmp_path: Path) -> None:
    fixture = _source_fixture(tmp_path)
    patches = _patch_public_boundaries(fixture)
    try:
        for active in patches:
            active.start()
        missing_preview = preview_virtual_remediation(RULE_ID, method_key="", file_path=fixture["source_path"].as_posix())
        stale_apply = apply_remediation(
            RULE_ID,
            method_key="workspace@revision:wrong.java#method:hash/0",
            file_path=fixture["source_path"].as_posix(),
            mode="dry_run",
            max_attempts=1,
        )
    finally:
        for active in reversed(patches):
            active.stop()
        _get_service.cache_clear()
        clear_policy_evaluation_cache()

    assert missing_preview == {"status": "INVALID", "error": "method_key is required", "violation_id": RULE_ID}
    assert stale_apply["status"] in {"NOT_FOUND", "STALE_SOURCE"}
    assert stale_apply["method_key"] == "workspace@revision:wrong.java#method:hash/0"
