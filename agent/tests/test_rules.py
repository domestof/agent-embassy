import rules


def test_first_match_wins_within_threshold():
    assert rules.evaluate("order.place", 100) == "mock_erp"
    assert rules.evaluate("order.place", 20000) == "mock_erp"


def test_above_threshold_falls_to_explicit_llm_rule():
    assert rules.evaluate("order.place", 20001) == "llm"


def test_unknown_action_type_matches_nothing():
    assert rules.evaluate("invoice.pay", 100) is None


def test_allowed_channels_returns_a_copy():
    channels = rules.allowed_channels()
    channels.append("injected")
    assert "injected" not in rules.allowed_channels()


def test_summary_reflects_loaded_config():
    summary = rules.summary()
    assert summary["allowed_channels"] == ["mock_erp", "slack_stub", "email_stub"]
    assert len(summary["rules"]) == 2


def test_shipped_llm_rule_declares_a_fallback():
    """Guards the invariant this file's docstring claims: every routing path
    is visible in rules.json. Without a fallback on the "llm" catch-all, the
    path taken by the shipped default (no AGENT_LLM_MODEL) was "fail", and it
    appeared nowhere in the file."""
    assert rules.fallback_channel("order.place", 40000) == "mock_erp"


def test_fallback_is_none_where_no_rule_matches():
    assert rules.fallback_channel("invoice.pay", 100) is None


def test_rule_matched_within_threshold_has_no_fallback():
    """Only the "llm" rule carries one -- a direct-channel rule needs none."""
    assert rules.fallback_channel("order.place", 100) is None
