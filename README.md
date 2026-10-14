# Secure Code Debugging & Review Assistant (Case Study 4)

Locally hosted AI assistance for ECU code understanding, debugging, MISRA-oriented and security review, with
structured, evidence-backed findings. Source code never leaves your boundary.

```
Streamlit UI --HTTP--> FastAPI (auth, RBAC, audit)
                          |
              +-----------+------------+
        Engine (review/ask/debug)   Services (users, repos, findings, path-level authz)
              |                            |
   rules, log parsers, guard        SQLite (users, findings, hash-chained audit)
   RAG: embeddings + vector store   Local LLM (Ollama / vLLM / llama.cpp) - optional
```

## Quick start
```bash
pip install -r requirements.txt
python -m app.cli bootstrap                      # prints demo credentials once (admin / alice=developer / bob=reviewer)
uvicorn app.main:app_factory --factory --port 8000
streamlit run ui/streamlit_app.py                # http://localhost:8501
pytest -q tests                                  # 15 tests
```
Works fully **offline with no model** (deterministic rules + extractive Q&A). To add a local LLM:
```bash
ollama pull llama3.1:8b
SCR_LLM_BACKEND=ollama SCR_LLM_URL=http://127.0.0.1:11434 SCR_LLM_MODEL=llama3.1:8b uvicorn app.main:app_factory --factory
```
(`SCR_LLM_BACKEND=openai_compat` for a vLLM / llama.cpp server.) Docker: `docker compose up` (see comments in the file).

## Document workflow -> implementation
| Case-study step | Where |
|---|---|
| 1 Authenticate + verify repo permissions | `auth.py`, `services.py` (`can_access`: allow/deny path prefixes, deny wins) |
| 2 Retrieve only authorised code + guidelines | `vectorstore.search(predicate=...)` filters **before** ranking; `guidelines.py` |
| 3 Collect compiler / static-analysis / runtime evidence | `analyzers/logs.py` (gcc/clang, cppcheck XML, ASan/UBSan/crash logs) |
| 4 Contextual findings + remediation | `analyzers/rules.py` (15 internal rules), `engine.py` (LLM enrichment) |
| 5 File, function, evidence, rule, confidence | every finding row; citations list code + guideline |
| 6 Developer / reviewer disposition | `PATCH /findings/{id}` - role-gated, rejection needs a comment |
| 7 Write approved findings to workflow system | `POST /findings/publish` -> `data/outbox/*.json` (+ optional allow-listed webhook) |

Also: repository-aware Q&A (`/ask`), function/module summaries with call + complexity data (`/summarize`),
log interpretation and root-cause candidates (`/debug`), CI gate (`python -m app.cli review --fail-on high`),
Markdown report (`/findings/export`), success metrics (`/metrics`: finding precision, % processed in boundary).

## Risk controls (from the document's risk table)
| Risk | Control implemented |
|---|---|
| Exposure of proprietary code | Local inference only; LLM/webhook host must be in `SCR_ALLOWED_HOSTS`; compose `internal` network; secrets redacted from evidence |
| False positives / unsafe fixes | Confidence scores, `likely_false_positive` downgrade, mandatory reviewer disposition; **no auto-merge/auto-fix** |
| Prompt injection via repo content | `guard.py`: injection lines redacted from prompts, content wrapped as untrusted data, model output screened, attempts reported as `ICR-SEC1` |
| Excess access to other modules | Path-level allow/deny; denied files are excluded from analysis, retrieval, findings lists and log mapping |
| Auditability | Hash-chained audit log (`/admin/audit` verifies the chain) |

## Extending
* **Rules:** add a `Rule` to `CATALOGUE` and a check in `run_rules`. Org rules: add `## ICR-Pxx Title` sections to `guidelines/*.md`.
* **Deviations:** `/* scr-ignore ICR-002: reason */` on or above the line.
* **Embeddings:** `SCR_EMBED_BACKEND=st` + `SCR_EMBED_MODEL=/path/to/local/bge-model` (needs `sentence-transformers`).
* **Vector DB:** `VectorStore` exposes `replace/search`; put FAISS/Chroma/Milvus behind the same two methods.

## Honest limitations
* Rules are regex/heuristics over a masked source model, not a compiler front-end. They complement certified tools
  (Polyspace, Helix QAC, Coverity), whose output can be fed in via the log parsers. "MISRA-oriented" is not MISRA-compliant;
  rule text is internal paraphrase with only rule numbers cross-referenced.
* The default hashing embedder is lexical; use BGE/E5 for better semantic recall.
* Auth is minimal PBKDF2 + signed tokens; put real SSO (OIDC) and TLS in front for production; SQLite -> PostgreSQL to scale.
* Not implemented: Git/PR diff review, SARIF export, Neo4j traceability.
