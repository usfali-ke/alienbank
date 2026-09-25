"""LLM provider wiring for the OpenAI Agents SDK.

Both AWS Bedrock (OpenAI-compatible endpoint) and a local Ollama server speak
the OpenAI Chat Completions API, so we drive them through the SDK's
``OpenAIChatCompletionsModel`` backed by a plain ``AsyncOpenAI`` client pointed
at the configured ``base_url``.
"""
from __future__ import annotations

from functools import lru_cache

from agents import OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI, OpenAI

from ..config import GUARD, INJECTION_GUARD, LLM, RAG

# The SDK's default tracing exporter phones home to OpenAI; disable it since we
# target Bedrock/Ollama and don't want spurious auth errors in the lab.
set_tracing_disabled(True)


@lru_cache(maxsize=1)
def _client() -> AsyncOpenAI:
    return AsyncOpenAI(api_key=LLM.api_key or "not-needed", base_url=LLM.base_url)


def get_model() -> OpenAIChatCompletionsModel:
    """Return the Agents-SDK model configured from the environment."""
    return OpenAIChatCompletionsModel(model=LLM.model, openai_client=_client())


def provider_summary() -> str:
    return f"{LLM.provider}:{LLM.model} @ {LLM.base_url}"


@lru_cache(maxsize=1)
def guard_client() -> AsyncOpenAI:
    """Client for the D2 guard model (a local Ollama moderation model)."""
    return AsyncOpenAI(api_key=GUARD.api_key or "ollama", base_url=GUARD.base_url)


@lru_cache(maxsize=1)
def injection_guard_client() -> AsyncOpenAI:
    """Client for the D6 injection guard's Ollama LLM-judge backend.

    Separate from ``guard_client`` (D2) so the injection judge can point at a
    different model/endpoint if desired; defaults to the same guard endpoint.
    """
    return AsyncOpenAI(api_key=INJECTION_GUARD.api_key or "ollama",
                       base_url=INJECTION_GUARD.base_url)


@lru_cache(maxsize=1)
def embed_client() -> OpenAI:
    """Sync client for the RAG embedding model (local Ollama, OpenAI-compatible)."""
    return OpenAI(api_key=RAG.api_key or "ollama", base_url=RAG.base_url)


@lru_cache(maxsize=1)
def analysis_client() -> OpenAI:
    """Sync client on the main LLM, used for one-shot analytical calls.

    The loan engine feeds a statement to the model and reads a single JSON reply,
    so a plain synchronous chat-completions call is simpler than the Agents-SDK
    runner. Points at the same provider/endpoint as the chat agent.
    """
    return OpenAI(api_key=LLM.api_key or "not-needed", base_url=LLM.base_url)
