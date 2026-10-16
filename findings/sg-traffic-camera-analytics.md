# sg-traffic-camera-analytics

Traffic-camera vehicle counting with a Kafka-API (Redpanda) streaming pipeline and a small read-only FastAPI view
of the latest state per camera (`src/tcam/stream/api.py`).

- Before: `255952d` (2026-10-14). After: `bda2f5d` (2026-10-15).
- Attack surface: the HTTP API (3 GET routes, no auth, meant for localhost) and the Redpanda broker started by
  `docker-compose.yml` (dev-container mode, no authentication).
- No Dockerfile of its own; the only image is the upstream `redpandadata/redpanda`.

## Triage

| # | Tool / rule | Where | Verdict | Severity in context | Action |
|---|---|---|---|---|---|
| C1 | Manual review (compose) | `docker-compose.yml` `ports: ["39092:39092"]` | True positive | Medium: an unauthenticated broker published on every interface; anyone who can reach the host can read the topics or write to them | Published on `127.0.0.1` unless `TCAM_BIND` is set; README and `run_stream.sh` show the opt-in for the WSL2 / remote-client setup (`6bc2c2f`) |
| C2 | Manual review (code) | `stream/api.py` consumer thread: `json.loads` and key lookups unguarded | True positive | Medium (availability): one malformed message on `tcam.camera-state` ended the consumer thread silently and froze the API's view; combined with C1, writable by anyone on the network | `apply_state()` validates and skips bad messages; 11 tests, 2 mutants (`8cf4e88`) |
| C3 | ZAP API scan 10021, 90004 | all API responses | True positive | Low | nosniff, X-Frame-Options, Referrer-Policy, CORP and a `default-src 'none'` CSP on JSON responses; 1 test, 1 mutant (`bda2f5d`) |
| C4 | Semgrep `github-actions-mutable-action-tag` (x2) | `ci.yml` | True positive | Low (supply chain) | Actions pinned to commit SHAs; `permissions: contents: read` (`1a56b79`) |
| C5 | Semgrep `dynamic-urllib-use-detected` (x5) | `archive.py`, `datamall.py`, `vlm_eval.py` | False positive | n/a | URLs are built from fixed `https://` API bases (data.gov.sg, LTA DataMall) or localhost Ollama; no user input reaches them |
| C6 | Semgrep `insecure-hash-algorithm-md5` (x3) | `archive.py`, `collect.py`, `producer.py` | False positive | n/a | MD5 is used to de-duplicate frames and to compare against the MD5 the archive API publishes; not a security control |
| C7 | Semgrep `insecure-request-object` (x1) | `scripts/vlm_eval.py` | False positive | n/a | Plain HTTP to a local Ollama server on `localhost:11434` |
| C8 | ZAP 10049 Storable and Cacheable Content | `/health` etc. | Informational | n/a | Left as is; public, non-sensitive JSON |

pip-audit (both requirement files), Trivy (dependencies, misconfiguration, secrets) and gitleaks (full history)
reported nothing before or after.

## CI added

`security` job: gitleaks over the full history, pip-audit on both requirement files, Semgrep (ERROR severity fails),
Trivy filesystem scan (fixable HIGH/CRITICAL fail). Scanner images pinned by digest.

## Residual risk

- The broker still has no authentication; binding to localhost limits who can reach it, it does not authenticate them.
- `requirements.txt` is unpinned, so a rebuild can pull different versions; pip-audit in CI resolves the current set.
