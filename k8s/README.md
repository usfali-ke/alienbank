# Deploying AlienBank to the local kind cluster

## 1. Build & load the image

```bash
docker build -t alienbank:0.2.0 .
kind load docker-image alienbank:0.2.0 --name kind
```

### Enabling the D6 prompt-injection guard (external, no image change)

The default image is the lean, vulnerable baseline. The **D6 injection guard**
(direct + indirect/RAG-hijack) runs as an **external HTTP call**, so nothing
heavy ships in the image (it stays ~1.4 GB — no torch, no baked models, no
re-download on pod start). Turn it on via the ConfigMap; it's level-gated to L2+.

Two backends:

- **Ollama LLM-judge** (fully local): point it at a reachable Ollama endpoint.
  ```yaml
  ALIENBANK_INJECTION_GUARD: "true"
  ALIENBANK_INJECTION_GUARD_BACKEND: "ollama"
  ALIENBANK_INJECTION_GUARD_BASE_URL: "http://<ollama-host>:11434/v1"
  ALIENBANK_INJECTION_GUARD_MODEL: "qwen2.5:3b-instruct"
  ALIENBANK_LEVEL: "2"
  ```
- **AWS Bedrock Guardrails** (managed API): create a guardrail with a
  **Prompt-attack** content filter (the input-side injection detector — grounding
  is output-only and doesn't apply to D6's input scan), then set its id/version.
  The base URL must be the native runtime host, not the chat proxy.
  ```yaml
  ALIENBANK_INJECTION_GUARD: "true"
  ALIENBANK_INJECTION_GUARD_BACKEND: "bedrock"
  ALIENBANK_BEDROCK_GUARDRAIL_ID: "<id>"
  ALIENBANK_BEDROCK_GUARDRAIL_BASE_URL: "https://bedrock-runtime.<region>.amazonaws.com"
  ALIENBANK_LEVEL: "2"
  ```
  (Reuses `AWS_BEARER_TOKEN_BEDROCK` from the Secret.)

If the backend is unreachable or unconfigured, D6 **fails open** — a missing
guardrail never masquerades as protection.

## 2. Create the Secret (from your local .env — never committed)

The token and session key stay out of git. Create the Secret imperatively:

```bash
kubectl create namespace alienbank --dry-run=client -o yaml | kubectl apply -f -

kubectl -n alienbank create secret generic alienbank-secrets \
  --from-literal=AWS_BEARER_TOKEN_BEDROCK="$(grep '^AWS_BEARER_TOKEN_BEDROCK=' .env | cut -d= -f2-)" \
  --from-literal=ALIENBANK_SECRET_KEY="$(grep '^ALIENBANK_SECRET_KEY=' .env | cut -d= -f2-)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 3. Apply the manifests

```bash
kubectl apply -f k8s/deploy.yaml
kubectl -n alienbank rollout status deploy/alienbank
```

## 4. Reach it

The kind cluster maps host ports 80/443 to the nginx ingress. `*.localtest.me`
resolves to 127.0.0.1, so no /etc/hosts edit is needed:

```
http://alienbank.localtest.me/
```

Log in with a seeded account (see the app README for demo credentials).

## Notes

- **Data is ephemeral** (`emptyDir`) — the SQLite DB and chroma index are seeded
  fresh on each pod start. Swap for a PVC to persist.
- **Ollama-backed RAG/guard** (levels 2–3, embeddings) are not reachable from
  in-cluster by default; the app logs and degrades gracefully. Point
  `OLLAMA_BASE_URL` at a reachable host to enable them.
