# Security Policy & Responsible Disclosure (ALASTOR `v5.1.0`)

## Dogfooding & Self-Audit Guarantee (`0 Unpatched Findings` • `533 Passing Tests`)

**ALASTOR `v5.1.0`** continuously audits its own backend (`FastAPI` / `Python`), frontend (`Next.js` / `TypeScript`), dependency lockfiles (`package-lock.json` / `requirements.txt`), Dockerfiles (`backend/Dockerfile`, `docker/sandbox/`), and GitHub Actions workflows (`.github/workflows/`) via `pytest` (`533` deterministic tests) and [`verify_harness.py`](./verify_harness.py), enforcing **0 unpatched self-audit findings** across all **33 deterministic CPG/SCA/IaC/Polyglot rules** (`RULE-1..33`, `SCA-1..2`, `IAC-1..3`), cognitive playbooks (`COG-1..5`), and secret scanners.

## Core Security Architecture & Threat Model Defenses

1. **Hostile-Repo Isolation ([`hostile_repo_guard.py`](./backend/engine/hostile_repo_guard.py)):**
   - Every host `git` invocation neutralizes `core.fsmonitor`, `core.hooksPath=/dev/null`, `core.sshCommand=false`, `core.pager`, `core.editor`, `gpg.*.program`, `credential.*.helper`, `remote.*`, `merge.*.driver`, and case-sensitive `filter.*` / `diff.*` drivers via `GIT_CONFIG_COUNT` / `KEY_n` / `VALUE_n`, and fails closed on repo-local `url.*.insteadOf` / `pushInsteadOf`.
   - Target `.env`, `.alastor.yaml`, and `config.yaml` files inside scanned repositories (including nested symlinks/NTFS junctions) are never loaded.
   - Clone URLs are restricted strictly to `https://`, `http://`, and `ssh://` (`git@`), blocking `file://`, `ext::`, and leading `-` option injection.
   - `alastor remediate --mode fix` enforces SQLite host-produced scan provenance (`host_fingerprint` + canonical `repo_path` + `commit_sha` + verified SHA-256 stage payload).
2. **OS-Enforced Dual Docker Egress-Proxy Sandbox ([`docker/sandbox/`](./docker/sandbox/), [`sandbox_orchestrator.py`](./backend/engine/sandbox_orchestrator.py)):**
   - Scanner image (`alastor-sandbox:local`) strips setuid/setgid (`chmod ug-s`), rejects private keys in `docker/sandbox/ca/`, runs `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --user 65534:65534`, and mounts target code `:ro`.
   - Mediated egress (`alastor-egress:local`) bridges traffic over a Unix socket into non-root Squid enforcing deny-by-default `CONNECT` to port `443` on validated public LLM API FQDNs only, with anti-DNS-rebinding `acl blocked_dst dst` blocking loopback, RFC1918, cloud metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), `0.0.0.0/8`, `::/128`, `::1`, ULA, and link-local ranges.
3. **DNS-Rebinding-Proof Live Exploit Verification ([`exploit_verification_engine.py`](./backend/engine/exploit_verification_engine.py)):**
   - Loopback-only default with explicit RFC1918/ULA staging opt-in; pins validated IPs directly at the `httpx` transport layer (preserving TLS SNI), permanently blocks public IPs, cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), redirects (`follow_redirects=False`), env proxies, and ALASTOR self-port `:8000`.
4. **Prompt-Injection Stripping, ReDoS AST Validation & Centralized Secret Scrubbing:**
   - All ReAct CPG agent tools (`agentic_react_loop.py`) read strictly `PolyglotScopeWalker` clean files (blocking `.env*`, key material, `.git/`, hostile instruction files, and confined/escaping symlinks), strip prompt injections (`strip_hostile_target_instructions`), validate search/custom-rule regexes via Python's `re._parser` AST (`validate_custom_rule_regex`), and scrub raw secrets + full PEM blocks (`scrub_raw_secrets_text`) prior to storage, LLM dispatch, PoC synthesis, or `.docx`/`.pdf`/SARIF export.
   - All SQLite stores (`cpg_embedded.db`, `checkpoints.db`) use WAL mode and strictly parameterized `?` queries; all local vault files enforce `0o700`/`0o600` atomic `fsync` + `os.replace` writes.

## Supported Versions

| Version | Supported | Status |
| :--- | :---: | :--- |
| **`5.1.x`** | ✅ Yes | **Current Release** — Full 5-Pillar ALASTOR v5.0 + Multi-Turn ReAct CPG Agent & Dual Docker Egress-Proxy Sandbox (`533` tests passing) |
| **`5.0.x`** | ✅ Yes | 18-Language Polyglot CPG, Dual Neo4j/SQLite WAL, 17-Lens Playbooks, S6/S8/S11, Live EV + `ev-replay`, 9-Command CLI/SDK, 6-Format Fusion, PR Gate, TestGen, 5-Framework Compliance & Microservice Stitching |
| **`4.0.x`** | ⚠️ Security Fixes Only | Daylight Studio, Directional 360° Graphs, Batch Auto-Fix, BYOK Frontier AI |
| **`3.0.x` and earlier** | ❌ End of Life | Upgrade to `v5.1.0` |

## Reporting a Vulnerability

If you discover a security vulnerability, sandbox bypass, ReDoS bypass, secret-redaction gap, or false-negative bypass in ALASTOR:
1. Please open a **GitHub Security Advisory** on this repository or submit an issue with a minimal reproducible test case.
2. Include the affected engine/endpoint, CPG path or attack vector, CWE identifier, and suggested remediation.
