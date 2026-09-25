from __future__ import annotations

import pytest

from alienbank import config, seclog


def test_secret_key_fails_closed_when_unset_or_placeholder(monkeypatch):
    monkeypatch.delenv("ALIENBANK_DEV_INSECURE", raising=False)
    for value in ("", config._INSECURE_SECRET):
        monkeypatch.setenv("ALIENBANK_SECRET_KEY", value)
        with pytest.raises(RuntimeError):
            config._resolve_secret_key()


def test_dev_insecure_mints_a_random_key_never_the_placeholder(monkeypatch):
    monkeypatch.setenv("ALIENBANK_SECRET_KEY", config._INSECURE_SECRET)
    monkeypatch.setenv("ALIENBANK_DEV_INSECURE", "true")
    with pytest.warns(UserWarning):
        a = config._resolve_secret_key()
    with pytest.warns(UserWarning):
        b = config._resolve_secret_key()
    assert a != b and config._INSECURE_SECRET not in (a, b) and len(a) == 64


def test_real_secret_key_is_used(monkeypatch):
    monkeypatch.setenv("ALIENBANK_SECRET_KEY", "k" * 64)
    assert config._resolve_secret_key() == "k" * 64


def test_level_is_clamped(monkeypatch):
    monkeypatch.setenv("ALIENBANK_LEVEL", "99")
    assert config.AppConfig.from_env().level == config.MAX_LEVEL
    config.set_level_override(-4)
    try:
        assert config.current_level() == config.MIN_LEVEL
    finally:
        config.set_level_override(None)


def test_llm_provider_selection(monkeypatch):
    monkeypatch.setenv("ALIENBANK_LLM_PROVIDER", "ollama")
    assert config.LLMConfig.from_env().provider == "ollama"
    monkeypatch.setenv("ALIENBANK_LLM_PROVIDER", "something-else")
    assert config.LLMConfig.from_env().provider == "bedrock"


def test_target_ref_is_stable_keyed_and_carries_no_username():
    a = seclog.target_ref("ana", "secret-1")
    assert a == seclog.target_ref("ana", "secret-1")
    assert a != seclog.target_ref("ana", "secret-2")
    assert a != seclog.target_ref("duncan", "secret-1")
    assert "ana" not in a
