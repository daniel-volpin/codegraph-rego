from codegraph.policy.trace import PolicyStateTrace, filter_predicate_trace, project_trace_profile


def test_filter_predicate_trace_ignores_strings_and_unsupported_keys():
    raw_eval = {
        "weak_hash_detected": True,
        "calls_md5": False,
        "some_random_string": "hello",
        "sql_keywords": ["select", "insert"],
        "violations": [],
        "unsupported_boolean": True,
    }
    filtered = filter_predicate_trace(raw_eval)

    # Keeps supported booleans
    assert filtered["weak_hash_detected"] is True
    assert filtered["calls_md5"] is False

    # Removes strings/lists
    assert "some_random_string" not in filtered
    assert "sql_keywords" not in filtered
    assert "violations" not in filtered

    # Removes unsupported booleans
    assert "unsupported_boolean" not in filtered


def test_filter_predicate_trace_handles_none():
    assert filter_predicate_trace(None) is None
    assert filter_predicate_trace({}) == {}


def test_policy_state_trace_instantiation():
    trace = PolicyStateTrace(
        package_path="data.iso27001",
        rule_id="ISO-A.10-WEAK-HASH",
        trace_source="package_root_eval",
        before_trace_raw={"weak_hash_detected": True},
        after_trace_raw={"weak_hash_detected": False},
        before_trace_filtered={"weak_hash_detected": True},
        after_trace_filtered={"weak_hash_detected": False},
        trace_fields_used=["weak_hash_detected"],
    )

    assert trace.package_path == "data.iso27001"
    assert trace.rule_id == "ISO-A.10-WEAK-HASH"
    assert trace.before_trace_filtered["weak_hash_detected"] is True
    assert trace.after_trace_filtered["weak_hash_detected"] is False


def test_project_trace_profile_weak_hash():
    filtered = {
        "weak_hash_detected": True,
        "source_md5": False,
        "calls_weak_hash": True,
        "analysis_md5": False,
    }
    profile = project_trace_profile("ISO-A.10-WEAK-HASH", filtered)

    assert profile.rule_id == "ISO-A.10-WEAK-HASH"
    assert profile.is_vulnerable is True
    assert profile.detected_via_source is False
    assert profile.detected_via_graph is True
    assert profile.detected_via_ast is False


def test_project_trace_profile_weak_random():
    filtered = {
        "insecure_random": True,
        "source_insecure_random": True,
        "calls_insecure_random": False,
        "analysis_insecure_random": True,
    }
    profile = project_trace_profile("ISO-A.10-WEAK-RANDOM", filtered)

    assert profile.is_vulnerable is True
    assert profile.detected_via_source is True
    assert profile.detected_via_graph is False
    assert profile.detected_via_ast is True


def test_project_trace_profile_weak_crypto():
    filtered = {
        "weak_cipher_detected": True,
        "source_weak_cipher": True,
        "analysis_weak_cipher": False,
    }
    profile = project_trace_profile("CWE-327", filtered)

    assert profile.is_vulnerable is True
    assert profile.detected_via_source is True
    assert profile.detected_via_graph is False
    assert profile.detected_via_ast is False


def test_project_trace_profile_missing_and_unsupported():
    assert project_trace_profile(None, {"weak_hash_detected": True}) is None
    assert project_trace_profile("ISO-A.10-WEAK-HASH", None) is None

    # Unsupported rule gracefully ignores
    assert project_trace_profile("SOME-OTHER-RULE", {"weak_hash_detected": True}) is None
