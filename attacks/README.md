# attacks/ — RAG poison fixtures (NOT part of the knowledge base)

These files are **attack payloads** for exercising the agentic-RAG security tests
in [`../RAG_SECURITY_PLAYBOOK.md`](../RAG_SECURITY_PLAYBOOK.md). They live here —
**outside `knowledge/`** — on purpose: the indexer only scans `knowledge/`, so
nothing here is indexed until you deliberately copy it in.

⚠️ **Never commit a poisoned file into `knowledge/`.** The workflow is always:
copy a payload into `knowledge/` → re-index → run the trigger → **remove it and
re-index to a clean state**.

`rag_poison/` payloads:
- `r1_indirect_transfer.md` — indirect prompt injection that tries to drive a
  `transfer_funds` call (OWASP LLM01 + LLM08 + LLM06).
- `r2_misinformation.md` — false "facts" to corrupt answers (LLM04 + LLM09).
- `r5_output_handling.md` — phishing link / markup smuggled in a chunk (LLM05).

See the playbook for the trigger prompts and expected behaviour per level.
