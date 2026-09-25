"""Agentic-RAG knowledge base for AlienBank.

Open-source stack, fully local:
  * Embeddings — Ollama ``bge-m3`` (1024-dim) via the OpenAI-compatible endpoint.
  * Vector store — ChromaDB, persisted under ``data/chroma``.

Markdown files under ``knowledge/`` are chunked by heading, embedded, and indexed.
The chat agent retrieves from here through the ``knowledge_search`` tool.

Build / rebuild the index:

    uv run alienbank-index            # build if empty
    uv run alienbank-index --rebuild  # drop and rebuild
"""
from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..config import KNOWLEDGE_DIR, RAG
from .guardrails import _D4_PATTERNS, _normalize
from .provider import embed_client

# Expected embedding dimensionality for the configured model. A mismatch means
# the model was swapped/re-pointed (LLM03 supply-chain drift) and would corrupt
# retrieval — we fail fast rather than silently degrade.
EXPECTED_DIM = {"bge-m3": 1024, "nomic-embed-text": 768, "all-minilm": 384}


# Folder -> audience mapping for RAG partitioning (LLM08). Anything under
# knowledge/internal/ is staff-only; everything else is public.
def _audience_for(rel_path: str) -> str:
    return "staff" if rel_path.startswith("internal/") else "public"


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
@dataclass
class Chunk:
    id: str
    text: str
    source: str
    title: str
    audience: str = "public"


def _chunk_markdown(path: Path, max_chars: int = 1200) -> list[Chunk]:
    """Split a markdown doc into heading-anchored chunks.

    Sections are split on ``##`` headings; long sections are further split on
    blank lines so no chunk greatly exceeds ``max_chars``.
    """
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(KNOWLEDGE_DIR).as_posix()

    # Split into (heading, body) sections on level-2 headings.
    parts = re.split(r"^(#{1,3} .+)$", text, flags=re.MULTILINE)
    sections: list[tuple[str, str]] = []
    if parts[0].strip():
        sections.append(("", parts[0].strip()))
    for i in range(1, len(parts), 2):
        heading = parts[i].lstrip("# ").strip()
        body = parts[i + 1].strip() if i + 1 < len(parts) else ""
        sections.append((heading, body))

    chunks: list[Chunk] = []
    n = 0
    for heading, body in sections:
        if not body:
            continue
        # Further split overly long bodies on blank lines.
        blocks, cur = [], ""
        for para in body.split("\n\n"):
            if len(cur) + len(para) + 2 > max_chars and cur:
                blocks.append(cur.strip())
                cur = para
            else:
                cur = f"{cur}\n\n{para}" if cur else para
        if cur.strip():
            blocks.append(cur.strip())

        for block in blocks:
            prefix = f"{heading}\n\n" if heading else ""
            chunks.append(Chunk(
                id=f"{rel}#{n}",
                text=f"{prefix}{block}",
                source=rel,
                title=heading or path.stem,
                audience=_audience_for(rel),
            ))
            n += 1
    return chunks


# ---------------------------------------------------------------------------
# Ingest validation (LLM04) — provenance + injection scan
# ---------------------------------------------------------------------------
def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _looks_injected(text: str) -> list[str]:
    """Return the D4 injection-pattern labels a chunk matches (empty = clean).

    A curated knowledge chunk should be pure data. Instruction-like text
    ("note for the assistant", tool-call syntax, "ignore previous", …) is the
    signature of a poisoned document, so we flag it at ingest.
    """
    norm = _normalize(text)
    return [label for pat, label in _D4_PATTERNS if re.search(pat, norm)]


def load_chunks() -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        chunks.extend(_chunk_markdown(path))
    return chunks


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------
def embed_texts(texts: list[str]) -> list[list[float]]:
    resp = embed_client().embeddings.create(model=RAG.embed_model, input=texts)
    embs = [d.embedding for d in resp.data]
    # LLM03 — guard against a silently swapped/re-pointed embedding model.
    expected = EXPECTED_DIM.get(RAG.embed_model.split(":")[0])
    if expected and embs and len(embs[0]) != expected:
        raise RuntimeError(
            f"Embedding dim mismatch for '{RAG.embed_model}': got {len(embs[0])}, "
            f"expected {expected}. The model may have changed — refusing to index "
            f"(would corrupt retrieval). Set ALIENBANK_EMBED_MODEL correctly or "
            f"rebuild the index.")
    return embs


# ---------------------------------------------------------------------------
# ChromaDB
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _collection():
    import chromadb

    client = chromadb.PersistentClient(path=RAG.chroma_path)
    # We supply our own embeddings, so no embedding_function is configured.
    return client.get_or_create_collection(
        name=RAG.collection, metadata={"hnsw:space": "cosine"}
    )


def index_count() -> int:
    try:
        return _collection().count()
    except Exception:  # noqa: BLE001
        return 0


def build_index(rebuild: bool = False, strict: bool = False) -> int:
    """Embed all knowledge chunks and (re)populate the Chroma collection.

    Each chunk is validated at ingest (LLM04): a content hash for provenance and
    an injection scan. Flagged chunks are tagged ``flagged=True`` in metadata (and
    dropped from retrieval); with ``strict`` they are refused entirely.
    """
    import chromadb

    client = chromadb.PersistentClient(path=RAG.chroma_path)
    if rebuild:
        try:
            client.delete_collection(RAG.collection)
        except Exception:  # noqa: BLE001
            pass
        _collection.cache_clear()

    col = client.get_or_create_collection(
        name=RAG.collection, metadata={"hnsw:space": "cosine"}
    )
    if not rebuild and col.count() > 0:
        return col.count()

    chunks = load_chunks()
    if not chunks:
        return 0

    flagged_total = 0
    kept: list[Chunk] = []
    meta: dict[str, dict] = {}
    for c in chunks:
        # The owasp/ corpus *describes* attacks (e.g. quotes "you are now a teller")
        # as teaching material, so injection-scanning it would false-positive. Only
        # scan corpora meant to be pure data (corporate/, internal/, and any
        # user-supplied docs) — that's where a real poisoned doc would land.
        labels = [] if c.source.startswith("owasp/") else _looks_injected(c.text)
        if labels:
            flagged_total += 1
            print(f"[ingest] FLAGGED {c.id} — injection-like content: {labels}")
            if strict:
                continue  # refuse to index poisoned content
        kept.append(c)
        meta[c.id] = {"source": c.source, "title": c.title, "audience": c.audience,
                      "sha256": _sha256(c.text), "flagged": bool(labels)}

    # Embed in batches to keep requests modest.
    batch = 32
    for i in range(0, len(kept), batch):
        part = kept[i:i + batch]
        embeddings = embed_texts([c.text for c in part])
        col.add(
            ids=[c.id for c in part],
            embeddings=embeddings,
            documents=[c.text for c in part],
            metadatas=[meta[c.id] for c in part],
        )
    if flagged_total:
        print(f"[ingest] {flagged_total} chunk(s) flagged as injection-like"
              + (" and refused (strict)" if strict else " (kept but excluded from retrieval)"))
    _collection.cache_clear()
    return col.count()


def search(query: str, top_k: int | None = None, *, allowed_audiences: set[str] | None = None) -> list[dict]:
    """Return the top-k knowledge chunks most relevant to ``query``.

    Always drops chunks flagged as injection-like at ingest (LLM04). When
    ``allowed_audiences`` is given (RAG partitioning, LLM08), only chunks whose
    ``audience`` is in that set are returned — e.g. a customer gets ``{"public"}``
    and never sees staff-only docs. When it's None, no partition filter is applied
    (the L0/L1 behaviour, where any indexed content is retrievable).
    """
    k = top_k or RAG.top_k
    col = _collection()
    if col.count() == 0:
        return []
    q_emb = embed_texts([query])[0]
    where = None
    if allowed_audiences is not None:
        where = {"audience": {"$in": list(allowed_audiences)}}
    # Over-fetch a little so post-filtering (flagged) still yields up to k.
    res = col.query(query_embeddings=[q_emb], n_results=max(k * 2, k + 4), where=where,
                    include=["documents", "metadatas", "distances"])
    out = []
    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    for doc, meta, dist in zip(docs, metas, dists):
        meta = meta or {}
        if meta.get("flagged"):
            continue  # never serve a poisoned chunk, at any level
        out.append({
            "text": doc,
            "source": meta.get("source", ""),
            "title": meta.get("title", ""),
            "audience": meta.get("audience", "public"),
            "score": round(1 - dist, 4),  # cosine distance -> similarity
        })
        if len(out) >= k:
            break
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the AlienBank knowledge index")
    parser.add_argument("--rebuild", action="store_true", help="drop and rebuild the index")
    parser.add_argument("--strict", action="store_true",
                        help="refuse to index chunks flagged as injection-like")
    parser.add_argument("--query", help="run a test query instead of building")
    args = parser.parse_args()

    if args.query:
        for i, hit in enumerate(search(args.query), 1):
            print(f"[{i}] ({hit['score']}) [{hit.get('audience','?')}] {hit['source']} — {hit['title']}")
            print("    " + hit["text"][:160].replace("\n", " ") + "…\n")
        return

    print(f"Loading knowledge from {KNOWLEDGE_DIR} …")
    n = build_index(rebuild=args.rebuild, strict=args.strict)
    print(f"Indexed {n} chunks into '{RAG.collection}' at {RAG.chroma_path} "
          f"(embeddings: {RAG.embed_model}).")


if __name__ == "__main__":
    main()
