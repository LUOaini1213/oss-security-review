# civil-buddy-sme (assessed; fixes not pushed)

Agent workbench for engineering and logistics drafting: a FastAPI gateway with browser pages, a token gate
(`packing_assistant/access_guard.py`), a Rust desktop workbench and a Docker/Caddy deployment kit.

- Assessed at `4d6ad08` (2026-10-13), the head of `main`.
- **Why no fixes were pushed:** while this review ran, the branch `codex/practical-workbench-20260930` (open draft
  PR #14) received commits on 2026-10-15, and it edits `.github/workflows/ci.yml` and `deploy/lightsail/test-local.sh`,
  the files the CI and Dockerfile changes below would touch. Pushing to `main` under active parallel work risked
  conflicts, so the findings and the proposed changes are recorded here for the owner to apply.
- Attack surface: every gateway route and WebSocket, behind the token gate; `/` and `/api/health` are public.

## What the review confirmed

The access control held up under the scans:

- With `CIVIL_TOKEN` set, ZAP's unauthenticated baseline reached only the "Access token required" page; with the
  token (sent as the `cb_token` cookie through ZAP's replacer, a throwaway value for this run, not kept in any report)
  it reached the pages and static files.
- The gate compares tokens with `hmac.compare_digest`, treats any forwarding header as remote, refuses to bind a
  non-loopback address without a token, and strips `?token=` into an HttpOnly, SameSite=Strict cookie with a 303.
- The deployment kit's Caddyfile already sets HSTS, nosniff, X-Frame-Options and Referrer-Policy and filters the token
  out of access logs.

## Triage

| # | Tool / rule | Where | Verdict | Severity in context | Proposed fix |
|---|---|---|---|---|---|
| B1 | Trivy misconfig DS-0002, DS-0026; `docker exec id` = root | `Dockerfile` | True positive | Medium: the gateway, which runs agent tools and parses uploaded files, runs as root | Add a non-root user owning `/app/output` and `/app/demo/out`, plus a HEALTHCHECK. Existing named volumes created by the root container need a one-time `chown` |
| B2 | ZAP baseline 10020, 10021, 10038, 10063 | gateway responses when served without Caddy (`docker compose up` publishes 8000) | True positive | Low to Medium | A small middleware adding nosniff, `frame-ancestors`, Referrer-Policy, Permissions-Policy; a CSP needs care because the pages use inline handlers |
| B3 | Trivy image | `python:3.11-slim` packaging tools | True positive, not reachable at run time | Low: 2 fixable HIGH, 7 MEDIUM, 1 LOW, 2 UNKNOWN | Pin the base by digest, upgrade setuptools and wheel, remove pip after install (as done in the other repos) |
| B4 | Trivy (Cargo.lock) GHSA-2mjx-qc3c-rqvc | `rustls` 0.23.43 in `workbench/` | True positive | Medium: TLS 1.3 handshake messages accepted across encryption-level boundaries; the workbench uses TLS as a client | `cargo update -p rustls --precise 0.23.45` |
| B5 | ZAP 10003 Vulnerable JS Library | `demo/static/vendor/vue.min.js` (Vue 2.7.16, CVE-2024-9506) | True positive | Low: ReDoS in the template parser on attacker-controlled templates; Vue 2 is end-of-life, so there is no fixed 2.x release | Track; migrating off Vue 2 is a larger change |
| B6 | npm audit | `esbuild` <= 0.24.2 (devDependency) | True positive, not exploitable here | Low: the advisory concerns esbuild's dev server; this repo only calls `esbuild.buildSync` in a test | Bump to >= 0.25 when convenient |
| B7 | Semgrep `github-actions-mutable-action-tag` (x12) | `ci.yml` | True positive | Low | Pin actions to commit SHAs |
| B8 | gitleaks (x3: 2 `generic-api-key`, 1 `private-key`) | `scripts/test_civil_review.py`, `test_model_loop.py`, `test_it_drafts.py` | False positive | n/a | All are synthetic markers in tests of the secret-redaction and `.env` refusal code (for example `DOTENV-MARKER-…`, `MII_SYNTHETIC_PRIVATE_ALPHA`). Allow-list them in `.gitleaks.toml` |
| B9 | Semgrep `sqlalchemy-execute-raw-query` (x12), `formatted-sql-query` (x6) | `storage.py`, `kb_search.py`, `retrieval/service.py`, `demo/local_retrieval.py` | False positive | n/a | Interpolated parts are `?` placeholder lists, integer PRAGMA constants and table names checked against a fixed tuple; values are bound |
| B10 | Semgrep `dangerous-subprocess-use-tainted-env-args` (x9), `python36-compatibility-Popen*` (x5), `subprocess-injection` (x1) | launcher, OCR/packing workers, OS sandbox, scripts, a test | False positive | n/a | Fixed argv lists (`sys.executable -m …`, `taskkill /PID <int>`); the environment is copied, not taken from requests |
| B11 | Semgrep `detected-jwt-token` (x1) | `scripts/test_it_drafts.py` | False positive | n/a | A truncated sample token used to test redaction |
| B12 | Semgrep `gha-curl-pipe-shell` (x1) | `ci.yml` | False positive | n/a | `curl … /api/audit | python3 -c 'json.load…'` parses JSON; nothing is executed |
| B13 | Semgrep `dynamic-urllib-use-detected` (x24), `insecure-request-object` (x5), `non-literal-import` (x8), others | scripts and tools | Mostly false positive | Low | Local-only URLs and plugin loading from fixed module lists; reviewed by sample, not line by line |

pip-audit on all 13 requirement files reported nothing.

## Residual risk

All items B1 to B7 are open until the owner applies them. The biggest practical one is B1 (root in the container).
