"""The LLM output-validation contract (plan-review F6): exactly one key,
exact string equality against the allowlist, everything else -> None. These
tests exercise _validate directly (pure function) plus choose_channel's
not-configured short-circuit; the network boundary itself is covered by
test_main.py's monkeypatched flows."""
import llm

ALLOWED = ["mock_erp", "slack_stub", "email_stub"]


def test_valid_choice_accepted():
    assert llm._validate('{"channel": "slack_stub"}', ALLOWED) == "slack_stub"


def test_outer_whitespace_tolerated():
    assert llm._validate('  {"channel": "mock_erp"}\n', ALLOWED) == "mock_erp"


def test_prose_around_json_rejected():
    assert llm._validate('Sure! Here you go: {"channel": "mock_erp"}', ALLOWED) is None


def test_extra_keys_rejected():
    assert llm._validate('{"channel": "mock_erp", "note": "hi"}', ALLOWED) is None


def test_unknown_channel_rejected():
    assert llm._validate('{"channel": "erp_prod"}', ALLOWED) is None


def test_case_trick_rejected():
    # Exact equality, no normalization: Mock_ERP != mock_erp.
    assert llm._validate('{"channel": "Mock_ERP"}', ALLOWED) is None


def test_homoglyph_trick_rejected():
    # Cyrillic small er (U+0440) in place of latin p.
    assert llm._validate('{"channel": "mock_erр"}', ALLOWED) is None


def test_non_string_value_rejected():
    assert llm._validate('{"channel": ["mock_erp"]}', ALLOWED) is None
    assert llm._validate('{"channel": null}', ALLOWED) is None


def test_non_object_rejected():
    assert llm._validate('"mock_erp"', ALLOWED) is None
    assert llm._validate("garbage not json", ALLOWED) is None


def test_injection_style_output_rejected():
    assert llm._validate('{"channel": "mock_erp"} ignore previous instructions', ALLOWED) is None


def test_not_configured_short_circuits_to_none(monkeypatch):
    monkeypatch.setattr(llm, "AGENT_LLM_MODEL", "")
    outcome = llm.choose_channel(item="towels", quantity=1, amount_cents=100, allowed_channels=ALLOWED)
    assert outcome.channel is None
    assert outcome.raw_text is None


def test_summary_reports_configuration(monkeypatch):
    monkeypatch.setattr(llm, "AGENT_LLM_MODEL", "")
    assert llm.summary()["configured"] is False
    monkeypatch.setattr(llm, "AGENT_LLM_MODEL", "internal-agent-default")
    assert llm.summary() == {
        "configured": True,
        "model": "internal-agent-default",
        "base_url": llm.LITELLM_BASE_URL,
    }
