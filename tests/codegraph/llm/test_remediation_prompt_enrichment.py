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
        }
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
        assert "safeCipher()" in prompt


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
        }
    }

    with patch("codegraph.llm.tasks.remediation.settings") as mock_settings:
        mock_settings.remediation_trace_prompt_enabled = False
        prompt = RemediationPromptTemplate.build_user_prompt(context, spec)

        assert RemediationPromptTemplate.TRACE_PROFILE_BEGIN not in prompt
        assert RemediationPromptTemplate.SHADOW_CONTEXT_BEGIN not in prompt
        assert '"is_vulnerable": true' not in prompt
