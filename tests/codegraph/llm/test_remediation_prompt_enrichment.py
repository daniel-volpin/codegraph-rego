from unittest.mock import patch

from codegraph.llm.tasks.remediation import RemediationPromptTemplate, RemediationTaskSpec


def test_remediation_prompt_trace_enrichment_enabled():
    spec = RemediationTaskSpec(
        rule_id="TEST-001",
        objective="Fix weak crypto",
        allowed_transformations=[],
        non_goals=[],
    )
    context = {
        "target_method": "com.example.Test.method()",
        "prompt_context": {
            "normalized_trace_profile": {
                "is_vulnerable": True,
                "detected_via_source": False,
                "detected_via_graph": False,
                "detected_via_ast": True,
            },
            "deterministic_baseline_available": True,
            "deterministic_diff_snippet": "--- before\n+++ after\n+ safeCipher()",
        },
    }

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = True
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.TRACE_PROFILE_BEGIN in prompt
        assert RemediationPromptTemplate.TRACE_PROFILE_END in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_END in prompt

        assert '"is_vulnerable": true' in prompt
        assert '"deterministic_baseline_available": true' in prompt
        # diff snippet must NOT leak into the prompt (oracle leak fix)
        assert "safeCipher()" not in prompt


def test_remediation_prompt_trace_enrichment_disabled():
    spec = RemediationTaskSpec(
        rule_id="TEST-001",
        objective="Fix weak crypto",
        allowed_transformations=[],
        non_goals=[],
    )
    context = {
        "target_method": "com.example.Test.method()",
        "prompt_context": {
            "normalized_trace_profile": {"is_vulnerable": True},
            "deterministic_baseline_available": True,
        },
    }

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = False
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.TRACE_PROFILE_BEGIN not in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN not in prompt
        assert '"is_vulnerable": true' not in prompt


def test_remediation_prompt_det_available_false_suppressed():
    """Shadow context must NOT be injected when det_available is False (no-op baseline)."""
    spec = RemediationTaskSpec(
        rule_id="TEST-001",
        objective="Fix weak crypto",
        allowed_transformations=[],
        non_goals=[],
    )
    context = {
        "target_method": "com.example.Test.method()",
        "prompt_context": {
            "deterministic_baseline_available": False,
            "deterministic_diff_snippet": "--- before\n+++ after",
        },
    }

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = True
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN not in prompt
        assert '"deterministic_baseline_available"' not in prompt


def test_remediation_prompt_normalized_trace_none_skipped():
    """Trace section must be skipped when normalized_trace_profile is None (injection rules)."""
    spec = RemediationTaskSpec(
        rule_id="ISO-A.8-INJECTION",
        objective="Fix injection",
        allowed_transformations=[],
        non_goals=[],
    )
    context = {
        "target_method": "com.example.Test.method()",
        "prompt_context": {
            "normalized_trace_profile": None,
            "deterministic_baseline_available": True,
        },
    }

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = True
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.TRACE_PROFILE_BEGIN not in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN in prompt


def test_remediation_prompt_empty_context_no_sections():
    """When prompt_context is empty, no enrichment sections should appear."""
    spec = RemediationTaskSpec(
        rule_id="TEST-001",
        objective="Fix weak crypto",
        allowed_transformations=[],
        non_goals=[],
    )
    context = {"target_method": "com.example.Test.method()", "prompt_context": {}}

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = True
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.TRACE_PROFILE_BEGIN not in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN not in prompt


def test_apply_flow_does_not_mutate_caller_prompt_context():
    """execute_apply_fix must not mutate the caller's prompt_context dict."""
    from codegraph.remediation.apply_flow import execute_apply_fix
    from unittest.mock import MagicMock

    caller_context = {
        "deterministic_baseline_available": True,
        "deterministic_diff_snippet": "some_diff",
    }
    original_keys = set(caller_context.keys())
    original_values = dict(caller_context)

    mock_service = MagicMock()
    mock_service.get_violation_context.return_value = {
        "rule_id": "ISO-A.10-WEAK-HASH",
        "target_method": "test()",
        "file_path": "/test.java",
    }
    mock_service.preflight_fixability_reason.return_value = "unsupported"

    try:
        execute_apply_fix(
            service=mock_service,
            violation_id="test",
            target_method="test()",
            file_path="/test.java",
            mode="dry_run",
            max_attempts=1,
            raw_capture_dir=None,
            build_command=None,
            prompt_context=caller_context,
        )
    except Exception:
        pass  # We only care about mutation, not execution success

    assert set(caller_context.keys()) == original_keys, (
        f"Caller dict was mutated — new keys: {set(caller_context.keys()) - original_keys}"
    )
    assert caller_context == original_values, "Caller dict values were mutated"
