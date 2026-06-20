# AegisAgent — Qdrant Semantic Audit Indexing

This guide outlines how AegisAgent integrates with **Qdrant** (a Rust-native vector database) to perform semantic search, intent mapping, and anomaly detection over agent audit logs.

---

## 1. Architecture Overview

AegisAgent uses a **hybrid database strategy** to optimize performance, reliability, and security:

1. **SQLite (Metadata & Transaction Log):** Relational tables (tenants, agents, policy configurations) and historical transactional records stay in SQLite. It is lightweight, serverless, and transaction-safe.
2. **Qdrant (Semantic Search & Observation Plane):** Agent Security Events (`AseEvent`) are asynchronously vectorized and indexed in Qdrant. This enables security operators to query audit logs by intent (e.g., *"find all actions conceptually similar to code exfiltration"*) rather than exact keyword matches.

### Asynchronous Execution Model (Non-Blocking)

To comply with AegisAgent's performance constraints (inline path `<75ms`), the Qdrant indexing pipeline runs entirely out-of-band:
* The hot `/v1/authorize` path registers decisions and yields control back to the SDK.
* The gateway emits the event onto the bounded `tokio::mpsc` channel.
* The background drain task (`events::drain` in [`events.rs`](file:///home/ems/AegisAgent/gateway/src/events.rs)) pops the event and spawns a background worker via `tokio::spawn`.
* The background worker calls the embedding generator and uploads the point with full event metadata payloads to Qdrant. Any network slowdown or service outage in the embedding provider or Qdrant never blocks gateway authorization.

```text
               HOT PATH (<75ms)
Agent  ──► /v1/authorize  ──► SQLite (audit log) 
                 │
                 │ emit (non-blocking)
                 ▼
         events::drain (asynchronous loop)
                 │
                 ▼ tokio::spawn (out-of-band task)
         Embedding Generator (ONNX or HTTP API) ──► Qdrant (Semantic Index)
```

---

## 2. Embedding Strategies: Local vs. Cloud API

To accommodate both air-gapped/private enterprise environments and simple cloud deployments, the gateway abstracts embedding generation under an `EmbeddingModel` trait:

### Strategy A: OpenAI-Compatible HTTP API (Default)
Offloads embedding generation to a standard OpenAI-compatible `/v1/embeddings` endpoint. 
* **Cloud providers:** Works directly with OpenAI, Cohere, or any hosted LLM provider.
* **Fully local deployments:** Works directly with local model servers like **Ollama** or **LocalAI** running side-by-side with the gateway.
* **Why it's used:** Zero binary footprint, fast compilation, and no native Dynamic Linker (`libonnxruntime.so`) dependencies in the default build.

### Strategy B: In-Process ONNX Model (Optional)
Uses the Qdrant-maintained `fastembed` crate to run the embedding model inside the gateway process.
* **Why it's used:** Truly self-contained, air-gapped execution. Zero external HTTP requests.
* **Enabling the strategy:** Enabled via the Cargo feature flag `local-embeddings` (e.g., `cargo build --features local-embeddings`).

---

## 3. Configuration Reference

Configure the Qdrant integration using the following environment variables:

| Env Var | Default | Description |
|---|---|---|
| `AEGIS_QDRANT_URL` | None (Disabled) | Endpoint for the Qdrant instance (e.g. `http://localhost:6334` for gRPC). If unset, Qdrant indexing is bypassed. |
| `AEGIS_QDRANT_API_KEY` | None | API Key / Token for secured Qdrant Cloud or self-hosted instances. |
| `AEGIS_QDRANT_COLLECTION` | `aegis_audit_events` | Collection name inside Qdrant. |
| `AEGIS_EMBEDDING_STRATEGY` | `api` | Either `api` (uses HTTP endpoint) or `local` (uses local ONNX engine; requires cargo feature `local-embeddings`). |
| `AEGIS_EMBEDDING_URL` | `https://api.openai.com/v1/embeddings` | Target OpenAI-compatible API endpoint (ignored if strategy is `local`). |
| `AEGIS_EMBEDDING_KEY` | None | Bearer token / API key for the embedding provider. |
| `AEGIS_EMBEDDING_MODEL` | `text-embedding-3-small` | The model name passed to the embedding API (or selected in `fastembed` if strategy is `local`). |
| `AEGIS_EMBEDDING_DIMENSION` | `1536` | Vector size matching the configured model (e.g. `1536` for `text-embedding-3-small`, `384` for `all-minilm-l6-v2`). |

---

## 4. Runbook: 100% Local Setup (Gateway + Ollama + Qdrant)

To run a fully private semantic audit engine locally, configure the stack as follows:

1. **Start Ollama & pull an embedding model:**
   ```bash
   ollama run all-minilm
   ```
2. **Start Qdrant container:**
   ```bash
   docker run -d -p 6333:6333 -p 6334:6334 qdrant/qdrant
   ```
3. **Configure and start the AegisAgent gateway:**
   ```bash
   export AEGIS_QDRANT_URL="http://127.0.0.1:6334"
   export AEGIS_EMBEDDING_STRATEGY="api"
   export AEGIS_EMBEDDING_URL="http://127.0.0.1:11434/v1/embeddings"
   export AEGIS_EMBEDDING_MODEL="all-minilm"
   export AEGIS_EMBEDDING_DIMENSION="384"
   
   cargo run --manifest-path gateway/Cargo.toml
   ```

---

## 5. Architectural Rationale & Trade-offs (Local ONNX vs. Cloud/Ollama API)

AegisAgent is an open-source, security-sensitive gateway. Designing the embedding and vectorization pipeline requires balancing operational simplicity, resource isolation, and deployment flexibility. Below is the research-backed rationale for our hybrid, trait-based approach:

### 1. The Dynamic Linker and Portability Bottleneck
* **Local ONNX Engine:** Running models inside the gateway via ONNX Runtime (`onnxruntime` C-library) requires binding to native shared libraries (`libonnxruntime.so`). In diverse open-source environments, this introduces significant platform dependency risks (glibc mismatches, missing CUDA/CPU dynamic libraries, and target architecture incompatibilities).
* **HTTP API Engine (Ollama/Cloud):** By using an HTTP client targeting standard OpenAI-compatible endpoints, the gateway compiles as a pure, lightweight Rust binary with no native C-linker dependencies. This guarantees out-of-the-box portability across standard CPU, GPU, containerized, and serverless environments.

### 2. Thread Starvation and CPU Resource Isolation
* Embedding vectorization (running matrix multiplication over transformer layers) is a heavy, CPU-bound machine learning task.
* In a high-throughput gateway environment (where `/v1/authorize` has a latency budget of `<75ms`), executing CPU-bound tensor operations in-process can starve the Tokio runtime threads, leading to increased response times for core authorization checks.
* Using an external engine (such as an Ollama sidecar container or a managed cloud endpoint) offloads LLM/embedding CPU computation entirely to a separate process/container, preserving the gateway's CPU cores for low-latency network I/O.
* For the in-process ONNX model (Strategy B), the gateway isolates tensor computation inside a `tokio::task::spawn_blocking` pool to prevent event-loop starvation.

### 3. Alignment with Modern Open-Source Standards
* Leading open-source data and AI platforms (e.g., LangChain, LlamaIndex, Qdrant Rust client) employ a decoupled architectural pattern. They prioritize API-based models for production scalability and portability, while leaving native ONNX engines (like `fastembed`) as opt-in features for self-contained desktop, testing, or air-gapped runtimes.
* AegisAgent's `EmbeddingModel` trait-based design directly mirrors this industry best practice. It provides a zero-dependency default build while allowing security engineers to compile with `--features local-embeddings` for strict, air-gapped environments.
