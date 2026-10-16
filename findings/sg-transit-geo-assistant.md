# sg-transit-geo-assistant

Plain-English questions about Singapore's bus network, answered with SQL over DuckDB (a local model or fixed
templates write the SQL) and shown on a MapLibre map. FastAPI back end, React front end served by nginx, both in
Docker Compose.

- Before: `3b59e13` (2026-10-13). After: `7852697` (2026-10-16).
- Attack surface: `POST /api/ask` (text-to-SQL), five GET routes, `/docs`; the nginx front end. No login, published on
  `127.0.0.1` only (documented in `docker-compose.yml`).
- The text-to-SQL path was already defended in depth before this review: an allow-list SQL validator
  (`backend/app/validator.py`: one SELECT, known tables, columns and functions, no table functions, CTE scoping),
  a read-only DuckDB connection with external access off and locked configuration, row/size/time limits, and a
  question screen. Nothing in this review got past it (see G9).

## Triage

| # | Tool / rule | Where | Verdict | Severity in context | Action |
|---|---|---|---|---|---|
| G1 | Trivy image | web image on `nginx:1.29-alpine` | True positive | High: 44 HIGH, 83 MEDIUM, 50 LOW, 2 UNKNOWN, all fixable. The 1.29 tag stopped getting rebuilds in April 2026 | `nginxinc/nginx-unprivileged:1.30-alpine`, pinned by digest: 1 MEDIUM left (`bacc7c2`) |
| G2 | Trivy misconfig DS-0002 / DS-0026 | `frontend/Dockerfile` | True positive | Medium (HIGH in Trivy): nginx master ran as root; no HEALTHCHECK | Unprivileged image, `USER 101`, port 8080, HEALTHCHECK (`bacc7c2`) |
| G3 | ZAP baseline 10020, 10021, 10038, 10063, 10036 | page and API responses | True positive | Medium/Low: no CSP, anti-clickjacking, nosniff or Permissions-Policy; nginx version in `Server` | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP; `server_tokens off`; uvicorn `--no-server-header` (`bacc7c2`, `c326f60`); `style-src 'unsafe-inline'` removed after a browser check (`96ec4b3`) |
| G4 | npm audit | `source-map-js` 1.2.1 (via Vite) | True positive, build-time only | Low in context (High in npm): event-loop DoS while parsing a crafted source map during a build | Lock file bumped to 1.2.2 (`1541e60`) |
| G5 | Trivy image | API image: base `pip` 25.0.1 | True positive, not reachable at run time | Low: 5 MEDIUM, 1 LOW fixable. Upgrading pip added 4 fixable HIGH (its vendored urllib3, msgpack, setuptools) | pip uninstalled from the runtime image (`7852697`) |
| G6 | Semgrep `github-actions-mutable-action-tag` (x5) | `ci.yml` | True positive | Low (supply chain) | Pinned to commit SHAs (`598287a`) |
| G7 | Semgrep `sqlalchemy-execute-raw-query` (x22, ERROR) and `formatted-sql-query` (x22) | `backend/app/build.py`, `scripts/prepare_from_sg_bus.py` | False positive | n/a | No SQLAlchemy in the project. The f-strings put paths to the build's own staging files and a constant SRID into DuckDB statements in offline build scripts. Excluded by rule ID in the CI Semgrep step, with the reason next to it |
| G8 | ZAP API 100001 Unexpected Content-Type (x12-13) | `/`, unknown paths | False positive | n/a | The single-page app returns `index.html` for unknown paths by design |
| G9 | ZAP API 40018 SQL Injection (High, Medium confidence), after-run only | `POST /api/ask`, `question` | False positive | n/a | Reproduced by hand: the example question with `AND 1=1` and with `AND 1=2` produced the same SQL and the same rows, and `John Doe AND 1=1` / `AND 1=2` were both refused (`no_template`). Question text never reaches SQL as text. The alert did not recur on the final run |
| G10 | ZAP 90004 COEP, 10049 cacheable, 10096 timestamp | page | Informational / accepted | Low | COEP would block the cross-origin basemap tiles; timestamps are in a bundled library |

pip-audit and gitleaks (full history) reported nothing before or after.

## CI added

- `security` job: gitleaks over the full history, pip-audit, `npm audit --audit-level=high`, Semgrep (ERROR severity
  fails, one documented exclusion), Trivy filesystem scan (dependencies, Dockerfiles, secrets; fixable HIGH/CRITICAL
  fail). Scanner images pinned by digest; actions pinned to commits.
- `docker` job: after the stack starts, checks CSP, nosniff, X-Frame-Options and Referrer-Policy on `/` and on the
  proxied `/api/health`, and that no `Server` header carries a version; then Trivy scans both built images (fixable
  HIGH/CRITICAL fail). The header check was run locally against both stacks: the fixed images pass, the old ones fail.
- First push failed CI once: the header check used `HEAD`, which the API answers with 405; fixed in `9c2b24b`.

## Residual risk

- API image: 44 HIGH and 2 fixable UNKNOWN (Debian `liblzma5`) remain in the `python:3.12-slim` base. The HIGH ones
  have no Debian fix yet; the digest has to be refreshed when the base is rebuilt.
- No authentication or rate limit on `/api/ask`; acceptable only because the stack binds to `127.0.0.1` (as the compose
  file says). A public deployment would need both.
- `/docs` keeps `script-src 'unsafe-inline'` and CDN scripts without SRI (FastAPI's Swagger page).
