# Security review of four of my public repositories

Six open-source scanners (Semgrep, pip-audit, npm audit, Trivy, gitleaks, OWASP ZAP) run on 2026-10-15 and 2026-10-16
against the four public repositories of mine that expose a web page or an HTTP API; every hit triaged by reading the
code; fixes pushed to three of them (17 commits).

- **Found and fixed:** the geo-assistant's web image went from 179 fixable vulnerabilities (44 HIGH) to 1 MEDIUM;
  two images stopped running as root; a Kafka consumer that froze the API on one malformed message now skips it.
- **Assessed only:** civil-buddy-sme, with a root container (B1, Medium) and six more items (B2 to B7) still open.
- **Limits:** passive ZAP baselines and OpenAPI-driven scans, not authenticated crawls; one person triaged; results
  depend on the scanners' vulnerability databases on the scan date.
- **Evidence:** the trimmed scanner reports are in `results/raw/`; `scripts/counts.py` rebuilds `results/counts.json`
  from them byte for byte, and `scripts/verify_readme.py` checks every number below against it (run in CI).

| Repository | What is exposed | Fixed in this review |
|---|---|---|
| [sg-transit-geo-assistant](https://github.com/LUOaini1213/sg-transit-geo-assistant) | FastAPI text-to-SQL API + React/nginx front end (Docker Compose) | yes, 7 commits |
| [fm-knowledge-assistant](https://github.com/LUOaini1213/fm-knowledge-assistant) | FastAPI search / question-answering API (Docker) | yes, 6 commits |
| [sg-traffic-camera-analytics](https://github.com/LUOaini1213/sg-traffic-camera-analytics) | read-only FastAPI view + Redpanda (Kafka API) broker (Compose) | yes, 4 commits |
| [civil-buddy-sme](https://github.com/LUOaini1213/civil-buddy-sme) | token-gated FastAPI gateway with browser pages (Docker, Caddy kit) | assessed only, see below |

Personal portfolio work, built with AI assistance (Claude) and checked by running it. The repositories are my own
projects; none of them holds real customer data.

## Method

| Layer | Tool | How it was run |
|---|---|---|
| SAST | Semgrep 1.181.0 | `p/default p/owasp-top-ten p/python p/javascript p/typescript p/dockerfile p/secrets`, 120 s per-file timeout (the default timed out on 28 files of civil-buddy-sme) |
| Python dependencies | pip-audit 2.10.1 | every tracked `requirements*.txt` |
| npm dependencies | npm audit (npm 11.17) | `--package-lock-only` on each lock file |
| Dependencies, Dockerfile / Compose misconfiguration, secrets in files | Trivy 0.76.0 `fs` | `--scanners vuln,misconfig,secret --offline-scan` |
| Container images | Trivy 0.76.0 `image` | each image built from the repository's Dockerfile on the base image current at scan time; "fixable" means Trivy lists a fixed version |
| Secrets in git history | gitleaks 8.30.1 | `gitleaks git` over every commit, output redacted |
| DAST | OWASP ZAP 2.17.0 | `zap-baseline.py` on the page, plus `zap-api-scan.py` from each FastAPI's `/openapi.json`; apps run locally in Docker on 127.0.0.1 |

Then every finding was triaged by reading the code it points at: true or false positive, severity in this
deployment, and whether it is exploitable. True positives were fixed in small commits, each with the scanner
evidence in its message; the repositories' own tests and mutation checks were run before pushing (in a clean container
for fm-knowledge-assistant and sg-traffic-camera-analytics, the front-end tests locally for sg-transit-geo-assistant),
and CI runs them on every push. A `security` job was added to each CI. The CI gates were themselves tested on known-bad input (the Trivy gate
on the pre-fix front end, the Semgrep gate without its documented exclusion, the gitleaks config on a planted key):
each failed as it should.

Per-repository triage tables: [`findings/`](findings). Scripts: [`scripts/`](scripts). Scanner reports, trimmed to
the fields the counts and the triage use (no secret values, matched text or commit authors): `results/raw/`.
Counts derived from them: `results/counts.json`.

## Results

Counts by severity (C critical, H high, M medium, L low). ZAP counts alert types, not instances. "After" is the head
of `main` once the fixes were in; Semgrep and ZAP counts that remain are explained in the findings files and are false
positives or accepted items unless listed under residual risk.

### sg-transit-geo-assistant

| Scanner | Before | After |
|---|---|---|
| Semgrep (SAST) | 22 H, 27 M | 22 H, 22 M |
| pip-audit (unique vulns) | 0 | 0 |
| npm audit | 1 H | 0 |
| Trivy fs: dependency CVEs | 0 | 0 |
| Trivy fs: Dockerfile/IaC misconfig | 1 H, 1 L | 0 |
| Trivy fs: secrets | 0 | 0 |
| gitleaks (full history) | 0 | 0 |
| Trivy image `api`: all | 44 H, 63 M, 62 L, 3 Unknown | 44 H, 58 M, 61 L, 3 Unknown |
| Trivy image `api`: fixable | 5 M, 1 L, 2 Unknown | 2 Unknown |
| Trivy image `web`: all | 44 H, 83 M, 50 L, 2 Unknown | 1 M |
| Trivy image `web`: fixable | 44 H, 83 M, 50 L, 2 Unknown | 1 M |
| ZAP baseline (web) (alert types) | 2 M, 7 L, 2 Info | 2 L, 2 Info |
| ZAP API scan (alert types) | 4 L, 3 Info | 1 L, 3 Info |

### fm-knowledge-assistant

| Scanner | Before | After |
|---|---|---|
| Semgrep (SAST) | 2 H, 6 M | 2 H, 3 M |
| pip-audit (unique vulns) | 0 | 0 |
| Trivy fs: dependency CVEs | 0 | 0 |
| Trivy fs: Dockerfile/IaC misconfig | 1 H | 0 |
| Trivy fs: secrets | 0 | 0 |
| gitleaks (full history) | 1 H | 0 |
| Trivy image `api`: all | 46 H, 64 M, 62 L, 3 Unknown | 44 H, 58 M, 61 L, 3 Unknown |
| Trivy image `api`: fixable | 2 H, 6 M, 1 L, 2 Unknown | 2 Unknown |
| ZAP baseline (web) (alert types) | 3 M, 6 L, 2 Info | 3 M, 3 L, 2 Info |
| ZAP API scan (alert types) | 5 L, 3 Info | 3 L, 2 Info |

### sg-traffic-camera-analytics

| Scanner | Before | After |
|---|---|---|
| Semgrep (SAST) | 11 M | 9 M |
| pip-audit (unique vulns) | 0 | 0 |
| Trivy fs: dependency CVEs | 0 | 0 |
| Trivy fs: Dockerfile/IaC misconfig | 0 | 0 |
| Trivy fs: secrets | 0 | 0 |
| gitleaks (full history) | 0 | 0 |
| ZAP baseline (web) (alert types) | 1 Info | 1 Info |
| ZAP API scan (alert types) | 2 L, 2 Info | 2 Info |

### civil-buddy-sme

| Scanner | Before | After |
|---|---|---|
| Semgrep (SAST) | 30 H, 63 M, 8 L | not re-run |
| pip-audit (unique vulns) | 0 | not re-run |
| npm audit | 1 M | not re-run |
| Trivy fs: dependency CVEs | 1 M | not re-run |
| Trivy fs: Dockerfile/IaC misconfig | 1 H, 1 L | not re-run |
| Trivy fs: secrets | 0 | not re-run |
| gitleaks (full history) | 3 H | not re-run |
| Trivy image `gateway`: all | 46 H, 65 M, 62 L, 3 Unknown | not re-run |
| Trivy image `gateway`: fixable | 2 H, 7 M, 1 L, 2 Unknown | not re-run |
| ZAP baseline (unauth) (alert types) | 2 M, 5 L, 2 Info | not re-run |
| ZAP baseline (auth) (alert types) | 3 M, 7 L, 4 Info | not re-run |

What moved, in plain terms:

- **Containers.** The geo-assistant's web image went from 179 fixable vulnerabilities (44 HIGH) to 1 MEDIUM by moving
  off an nginx tag that had stopped being rebuilt. The two Python images lost every fixable HIGH and MEDIUM: pip,
  which they do not use at run time, is removed. Both images that ran as root now run as unprivileged users.
- **Browser hardening.** The fm and camera APIs now send CSP, nosniff, anti-clickjacking, Referrer-Policy and CORP
  headers themselves; the geo API and front end get them from the nginx proxy, the only port the geo stack publishes
  (the geo API run directly with uvicorn sends none); the medium-risk ZAP alerts on the geo page went from 2 to 0. fm's three remaining
  medium alerts are on FastAPI's own Swagger page (inline bootstrap script and style, CDN files without SRI).
- **Code.** The camera API's Kafka consumer died on the first malformed message, freezing the API; it now skips bad
  messages (11 tests, 2 mutation cases). The Redpanda broker, which has no authentication, is no longer published on
  every interface.
- **Supply chain and CI.** Actions are pinned to commits and every workflow token is read-only; the CI of each
  fixed repository now runs gitleaks, pip-audit, npm audit where relevant, Semgrep and Trivy, and the Docker images
  of the geo-assistant and fm are scanned after they are built.
- **Secrets.** gitleaks found 4 hits across the four histories (1 in fm, 3 in civil-buddy-sme). All four are false
  positives: a SHA-256 file hash in an evaluation report, and synthetic markers in tests of the redaction code. No
  credential needed rotating. fm's hit is allow-listed narrowly in `.gitleaks.toml`.
- **What stayed.** In the three fixed repositories, Semgrep's remaining HIGH counts are one rule, `sqlalchemy-execute-raw-query`, firing on DuckDB and
  SQLite calls in projects with no SQLAlchemy; each match was read (findings G7, F7, B9). The geo and fm CI exclude
  that rule by ID with the reason written next to it.

## Remediation commits

| Repository | Commits (oldest first) |
|---|---|
| sg-transit-geo-assistant | `bacc7c2` unprivileged nginx 1.30 + security headers; `c326f60` pinned API base, no Server header; `1541e60` source-map-js 1.2.2; `598287a` CI: pinned actions + security scanning; `9c2b24b` CI header check uses GET; `96ec4b3` no `style-src 'unsafe-inline'`; `7852697` pip removed from the API image |
| fm-knowledge-assistant | `7b2c941` non-root user, pinned base; `376532e` security headers + tests + mutants; `6f2d318` `.gitleaks.toml` for the one false positive; `94e25e2` CI: pinned actions, image user check, image scan, security job; `97a4543` pip removed instead of upgraded; `f46ecae` CSP for `/docs`, CORP, Permissions-Policy |
| sg-traffic-camera-analytics | `8cf4e88` malformed state messages skipped + tests + mutants; `6bc2c2f` broker on 127.0.0.1 by default; `1a56b79` CI: pinned actions + security job; `bda2f5d` security headers + test + mutant |

CI was green on the head of `main` of all three when last checked, on 2026-11-09 (geo `35afb40`, fm `427472b`,
camera `bda2f5d`). Two intermediate pushes failed CI and were fixed by the next commit: the geo
header check first used `HEAD`, which the API answers with 405 (`9c2b24b`), and fm's new image gate caught the HIGH
CVEs that an upgraded pip vendors (`97a4543`). The second one is the gate doing its job on my own change.

## civil-buddy-sme: assessed, not changed

During the review another line of work on this repository was active (an open draft PR whose branch received commits
on 2026-10-15 and edits the CI workflow and the deployment test script). To avoid conflicting with it, nothing was
pushed. [`findings/civil-buddy-sme.md`](findings/civil-buddy-sme.md) lists the open items and the proposed fixes:
root user in the container (B1), missing headers when served without the Caddy proxy (B2), base-image packaging tools
(B3), `rustls` 0.23.43 in the Rust workbench (B4), Vue 2.7.16 (B5) and esbuild (B6, not exploitable here). The access
token gate itself held: unauthenticated, ZAP reached only the "token required" page. ZAP ran there as a baseline
scan without and with the token, not as an OpenAPI scan.

Status on 2026-11-09: none of B1 to B8 is applied on civil-buddy-sme `main` (`304d7de`), and there is no tracking
issue yet. Two pull requests were merged to `main` since the review (#16 on 2026-10-19, #19 on 2026-11-03), and
draft PR #14 is still open.

## Residual risk

- **No authentication or rate limiting** on the geo-assistant and fm APIs. Both are documented as local services and
  the geo stack binds to 127.0.0.1; neither should be put on a public address as is.
- **Base-image CVEs without a fix.** 44 HIGH in Debian packages of `python:3.12-slim` / `python:3.11-slim` have no
  Debian fix yet, and 2 `liblzma5` UNKNOWN wait for an upstream rebuild. The bases are pinned by digest, so someone
  has to refresh them; the CI image scans fail on fixable HIGH/CRITICAL, which is the signal to do it.
- **Unpinned Python requirements** in fm and the camera repository: builds are not byte-for-byte reproducible, and
  pip-audit checks what resolves today.
- **The Redpanda broker has no authentication.** Binding to localhost limits who can reach it.
- **Swagger pages** keep `'unsafe-inline'` and CDN scripts without SRI.
- **Coverage limits.** ZAP ran passive baselines and an OpenAPI-driven active scan, not an authenticated crawl of
  every workflow; fm's API ran without its document index (the source PDFs may not be redistributed), so `/search` and
  `/ask` answered 500 during the scan. Semgrep was not run with Rust rules on civil-buddy-sme's workbench. Findings
  were triaged by one person reading the code.

## Reproduce

Check the committed numbers (Python 3.11, standard library only, Windows or Linux):

```
python scripts/counts.py --base results/raw --check   # counts.json == what the trimmed reports give
python scripts/verify_readme.py                       # README and findings/ numbers == counts.json
python scripts/verify_readme.py --online              # also: every cited commit is on its repo's default branch
python -m unittest discover -s tests -v
```

Re-run the scans (Linux or WSL with Docker; Semgrep, pip-audit, Trivy and gitleaks on `PATH`, the scripts also look in
`~/.local/bin`). The vulnerability databases move, so a re-run gives today's counts, not the ones above.

```
export WORK=$HOME/sec                     # clones in $WORK/<repo>, reports in $WORK/_results/<repo>/<phase>/
git clone https://github.com/LUOaini1213/<repo> $WORK/<repo>
git -C $WORK/<repo> checkout <before or after SHA from results/scanned_commits.json>
scripts/secscan.sh <repo> <before|after>                    # Semgrep, pip-audit, Trivy fs, gitleaks
(cd $WORK/<repo>/<dir with package-lock.json> && npm audit --package-lock-only --json    > $WORK/_results/<repo>/<phase>/npm-audit_<dir>.json)   # geo: frontend, civil-buddy-sme: root
docker compose build                                         # in the clone, then:
scripts/img.sh <repo> <phase> <label> <image>               # labels: api, web (geo), api (fm), gateway (civil-buddy-sme)
scripts/seczap.sh <repo> <phase> web baseline http://127.0.0.1:<port>/            # app running locally
scripts/seczap.sh <repo> <phase> api api http://127.0.0.1:<port>/openapi.json   # civil-buddy-sme: unauth/auth baselines
python scripts/counts.py --out /tmp/counts.json             # reads $WORK/_results; exits 2 if it finds nothing
python scripts/trim_raw.py --dst /tmp/raw                   # the trimmed copy committed as results/raw/
```

`scripts/cisec.sh <repo>` replays a repository's CI security gates on `$WORK/<repo>`. `scripts/gate_mut.sh` checks
that the gates fail on known-bad input; it expects a clone of the pre-fix geo commit (`3b59e13`) at
`$WORK/_before_geo`. ZAP is pinned to `zaproxy:2.17.0` by digest, Trivy to 0.76.0 and gitleaks to 8.30.1 in the CI
replays.

## Licence

MIT, see [LICENSE](LICENSE). Third-party material is not covered: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
