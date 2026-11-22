# Project Handoff & AI Context — Service Side (Partner A)

## 1. Project & Role Overview
- **Course / Assignment:** IT 7075C — Final Project: An AI Security Analyst for Your Own Lab (Due Dec 4, 2026)
- **Partner A (Ben Bilenko — Service Side):** Completed and verified.
  - **Target Lab:** Metasploitable 2 / vulnerable service environment bound to `127.0.0.1` (`2121/tcp` FTP `vsFTPd 2.3.4`, `8080/tcp` HTTP `Apache/2.2.8 (Ubuntu) DAV/2` + `PHP/5.2.4-2ubuntu5.10`).
  - **Artifacts Delivered:** `recon_server.py`, `cve_knowledge_base.md`, `SOURCES.md`, and `stages_1_to_3_2.ipynb` (with saved outputs).
- **Partner B (Web Side — Next Steps):**
  - Build and test the web target (OWASP Juice Shop, DVWA, or WebGoat on `127.0.0.1`), 3+ web MCP scanners, and `web_security_kb.md`.
  - Merge both toolsets and knowledge bases into a unified Stage 3 agent, run the joint model benchmark (including Partner B's paid OpenAI API key), and co-produce the final report, repository, and video.

---

## 2. Service-Side Architecture & Files (`final_project/`)

### A. `recon_server.py` (MCP Server over `stdio`)
- **Framework:** `FastMCP("ServiceReconServer")` over `stdio`.
- **Guardrail 1 — Fail-Closed Scope Allowlist:** `ALLOWED_TARGETS = {"127.0.0.1"}`. Every tool calls `_check_scope(target)` on its first line and immediately returns `REFUSED: Target '<target>' is outside the authorized allowlist ['127.0.0.1'].` for any out-of-scope IP/host (verified against `8.8.8.8`).
- **Guardrail 2 — Human-in-the-Loop Gate:** `nmap_service_scan` proposes its exact call and blocks execution until the operator types `APPROVE`.
- **MCP Tools Exposed (4 read-only/recon scanners):**
  1. `banner_grab(target: str, port: int, timeout: float = 2.0) -> str`
     - *Metasploit equivalent:* `auxiliary/scanner/portscan/tcp` / banner grabber (`socket`).
     - *Verified output:* `target=127.0.0.1 port=2121 state=open banner='220 (vsFTPd 2.3.4)'`
  2. `anonymous_ftp_check(target: str, port: int = 2121, timeout: float = 3.0) -> str`
     - *Metasploit equivalent:* `auxiliary/scanner/ftp/anonymous` (`ftplib`).
     - *Verified output:* `target=127.0.0.1 port=2121 anonymous_login=ALLOWED welcome='220 (vsFTPd 2.3.4)' response='230 Login successful.' sample_entries=[]`
  3. `http_probe(target: str, port: int = 8080, path: str = "/", timeout: float = 3.0) -> str`
     - *Metasploit equivalent:* `auxiliary/scanner/http/http_version` (`urllib.request`).
     - *Verified output:* `url=http://127.0.0.1:8080/ status=200 server=Apache/2.2.8 (Ubuntu) DAV/2 x_powered_by=PHP/5.2.4-2ubuntu5.10`
  4. `nmap_service_scan(target: str, ports: str = "2121,8080") -> str`
     - *Metasploit equivalent:* `db_nmap -sV` (`subprocess` calling Nmap 7.80).
     - *Verified output (after `APPROVE`):* `2121/tcp open ftp vsftpd 2.3.4` and `8080/tcp open http Apache httpd 2.2.8 ((Ubuntu) DAV/2)` (`8.01s`).

### B. `cve_knowledge_base.md` & `SOURCES.md`
- **4 Grounded Service Entries (all formatted with `##` headers):**
  1. `vsFTPd 2.3.4` — **Critical** (`CVE-2011-2523`, `CWE-78`)
  2. `Anonymous FTP Login Enabled` — **High** (`CWE-220`, `CWE-287`)
  3. `Apache HTTP Server 2.2.8 (DAV/2)` — **High** (`CVE-2017-9798`, `CVE-2014-0118`, `CVE-2013-6438`, `CWE-1104`)
  4. `PHP 5.2.4 (Ubuntu 5.2.4-2ubuntu5.10)` — **High** (`CVE-2010-2225`, `CVE-2011-1398`, `CWE-200`)
- **Coverage Metrics (Service Side):**
  - **Before KB expansion:** `1/4` (`25%`) grounded (`vsFTPd 2.3.4` only; anonymous FTP, Apache 2.2.8/DAV/2, and PHP 5.2.4 were ungrounded gaps).
  - **After KB expansion:** `4/4` (`100%`) grounded (`Loaded 4 findings and 4 KB sections from cve_knowledge_base.md`).
  - **Remaining Service Gaps:** Active exploit confirmation (e.g., triggering the vsFTPd backdoor on TCP 6200) and authenticated host/config file auditing beyond read-only network probes.

---

## 3. Notebook Results & Model Benchmark (`stages_1_to_3_2.ipynb`)
- **Stage 1 (Ungrounded Chain — `2.47s`):** Without KB context, the model hallucinated/guessed unverified CVEs from memory (e.g., `CVE-2011-2524` for vsFTPd, `CVE-2010-2861`–`2864` and `CVE-2011-3192` for Apache, and `CVE-2011-3544`–`3546` for PHP) and assumed host OS/firewall configuration (`apt-get` / `ufw`) not visible in network banners.
- **Stage 2 (Grounded RAG Chain — `1.13s`):** Grounded strictly against `cve_knowledge_base.md`; eliminated invented CVEs and mapped each finding to exact KB severity, CVE/CWE IDs, and remediation.
- **Two-Model Comparison (Service Findings):**
  | Model | Hosting / Endpoint | KB Refs Matched | Latency | Cost | Data Exposure |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | `qwen2.5:3b` | Local Ollama (`127.0.0.1:11434`) | `8/8` | `4.45s` | `$0` (local hardware) | Local only (no external API) |
  | `openai/gpt-oss-20b` | Groq Cloud API | `0/8` (paraphrased) | `1.32s` | `$0` (free tier) | External (Groq API endpoint) |

### Switching the Cloud API Slot to Partner B's Paid OpenAI API
`stages_1_to_3_2.ipynb` already uses `langchain_openai.ChatOpenAI`. To run the final team benchmark using Partner B's paid OpenAI key:
1. Add `OPENAI_API_KEY=...` to your local `.env` file (**never commit `.env` to Git** — `-10 pts` penalty).
2. Replace the Groq `ChatOpenAI` initialization with:
   ```python
   cloud_llm = ChatOpenAI(
       model="gpt-4o-mini",  # or "gpt-4o"
       api_key=os.getenv("OPENAI_API_KEY"),
       temperature=0,
   )