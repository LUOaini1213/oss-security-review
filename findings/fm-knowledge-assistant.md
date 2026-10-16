# fm-knowledge-assistant

Cited search and question answering over Singapore building and facilities-management codes. FastAPI service
(`/health`, `/search`, `/ask`, `/extract`) in a Docker image; the index is built at first start from official PDFs.

- Before: `f38fc3d` (2026-10-14). After: `f46ecae` (2026-10-16).
- Attack surface: four JSON routes and `/docs`, no authentication (the README presents it as a local service).

## Triage

| # | Tool / rule | Where | Verdict | Severity in context | Action |
|---|---|---|---|---|---|
| F1 | Trivy misconfig DS-0002 | `Dockerfile` | True positive | Medium (HIGH in Trivy): the API, the PDF download and the index build all ran as root | uid 10001 `app`, owning only `data/` and `.cache`; CI checks the image user (`7b2c941`) |
| F2 | Trivy image | `python:3.11-slim` packaging tools | True positive, not reachable at run time | Low: 2 fixable HIGH (`wheel` 0.45.1, `jaraco.context` vendored in setuptools) and pip 24.0 MEDIUMs | setuptools and wheel upgraded; pip removed after install (`7b2c941`, `97a4543`) |
| F3 | Trivy image (CI) | pip 26.2.1's vendored urllib3 2.7.0, msgpack 1.1.2, setuptools 70.3.0 | True positive, introduced by the first fix | Low (4 fixable HIGH) | The CI image gate failed on `94e25e2`; pip is now uninstalled instead of upgraded (`97a4543`) |
| F4 | ZAP baseline/API 10020, 10021, 10038, 10063, 90004 | all responses | True positive | Low | nosniff, X-Frame-Options, Referrer-Policy, `Cache-Control: no-store`, CORP, Permissions-Policy; CSP `default-src 'none'` on JSON and a scoped policy on `/docs` (`376532e`, `f46ecae`) |
| F5 | Semgrep `github-actions-mutable-action-tag` (x3) | `ci.yml` | True positive | Low | Pinned to commit SHAs; `permissions: contents: read` (`94e25e2`) |
| F6 | gitleaks `generic-api-key` (x1 in history) | `eval/results/claim_guard.json` | False positive | n/a | The value is the SHA-256 of `src/fmka/api.py` (the key contains "api"). `.gitleaks.toml` allows only 64-hex source-file hashes on that file's lines; checked: 2 hits without it, 0 with it, 2 with its path pattern broken (`6f2d318`) |
| F7 | Semgrep `sqlalchemy-execute-raw-query` (x2, ERROR), `formatted-sql-query` | `src/fmka/retrieval.py` | False positive | n/a | No SQLAlchemy. The f-strings format the integer vector dimension and `int(k)`; the query vector and allowed ids are bound parameters |
| F8 | Semgrep `exec-detected` (x2) | `eval/eval_claim_guard.py` | False positive | n/a | Executes this repository's own frozen baseline source read from `git show` of a fixed commit, for an offline comparison |
| F9 | ZAP API 100000 / 10023 / 90022 | `POST /search`, `/ask` | Artefact of the test setup | n/a | The DAST run started the API without building the index (that needs the official PDFs), so these routes returned 500. The body is Starlette's generic "Internal Server Error", no traceback |
| F10 | ZAP baseline 10055 `script-src` and `style-src 'unsafe-inline'`, 90003 no SRI, 10017 cross-domain script | `/docs` | Accepted | Low | FastAPI's Swagger page loads its bundle from cdn.jsdelivr.net with an inline bootstrap |

pip-audit reported nothing before or after (the requirements are unpinned, so it audits the versions that resolve
today).

## CI added

- `docker` job: the image must run as `app`; Trivy image scan (fixable HIGH/CRITICAL fail).
- `security` job: gitleaks (full history, with the documented exception), pip-audit, Semgrep (ERROR severity fails,
  one documented exclusion), Trivy filesystem scan.
- Tests: `tests/test_security_headers.py`; `tests/mutate.py` gained two mutants (52 in total), both killed.

## Residual risk

- No authentication or rate limit on `/ask`, which can call a hosted model when one is configured: fine for a local
  demo, not for a public endpoint.
- Unpinned `requirements.txt`; the image is reproducible only up to the pinned base digest.
- 44 HIGH in Debian packages of the base image have no Debian fix yet; 2 fixable UNKNOWN (`liblzma5`) wait for an
  upstream rebuild.
