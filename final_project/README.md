# Final Project: AI Security Analyst for Your Own Lab

Unified capstone workspace combining service-side reconnaissance (Metasploitable 2 / localhost service ports `2121`, `8080`) and web-side reconnaissance (OWASP Juice Shop / localhost port `3000`) through a single Model Context Protocol (MCP) server (`recon_server.py`) and notebook (`final_project.ipynb`).

## Contents
- `recon_server.py` — Unified MCP server exposing service and web read-only scanners behind a shared `127.0.0.1` fail-closed allowlist.
- `final_project.ipynb` — End-to-end workflow and model comparison notebook with saved outputs.
- `cve_knowledge_base.md` — Service-side vulnerability knowledge base (CVEs, CWEs, severities, and remediations).
- `web_security_kb.md` — Web-side security knowledge base (OWASP/CWE mappings, severities, and remediations).
- `SOURCES.md` — Consolidated references and advisories for both sides.
- `results/` — Saved scan and benchmark outputs.
- `CONTRIBUTIONS.md` — Partner responsibilities and sign-off.
- `.env.example` — Environment variable template (`.env` is never committed).

## Guardrails
1. **Scope Allowlist (Fail Closed):** Every tool validates the target against `127.0.0.1` (and allowed web port `3000`) before making any network connection, immediately refusing out-of-scope targets such as `8.8.8.8`.
2. **Human Approval Gate:** Proposed actions pause for explicit `APPROVE` input before executing.

## Setup
1. Copy `.env.example` to `.env` and populate `OPENAI_API_KEY` (keep `OPENAI_MODEL=gpt-4o-mini`, `OLLAMA_BASE_URL=http://127.0.0.1:11434`, and `OLLAMA_MODEL=qwen2.5:3b`).
2. Start local lab services on `127.0.0.1` (`2121`, `8080`, and `3000`).
3. Run all cells in `final_project.ipynb` with the project `.venv` kernel and save outputs.
