#!/bin/bash
# usage: secscan.sh <repo> <phase> [tools] [srcdir]   tools: comma list of semgrep,pipaudit,trivy,gitleaks (default all)
export PATH=$HOME/.local/bin:$PATH
export SEMGREP_SEND_METRICS=off
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="*"
R=$1; P=$2; TOOLS=${3:-semgrep,pipaudit,trivy,gitleaks}
SRC=${4:-${WORK:-$HOME/sec}/$R}
OUT=${WORK:-$HOME/sec}/_results/$R/$P
mkdir -p "$OUT"
cd "$SRC" || exit 1
git rev-parse HEAD > "$OUT/HEAD.txt" 2>/dev/null
date -u +%FT%TZ > "$OUT/scanned_at.txt"

if [[ $TOOLS == *semgrep* ]]; then
  echo "[$R/$P] semgrep"
  semgrep scan --metrics=off --disable-version-check --timeout 120 --timeout-threshold 0 --max-target-bytes 3000000 \
    --config p/default --config p/owasp-top-ten --config p/python --config p/javascript \
    --config p/typescript --config p/dockerfile --config p/secrets \
    --json -o "$OUT/semgrep.json" -q . 2> "$OUT/semgrep.err"
  echo "semgrep exit $?"
fi

if [[ $TOOLS == *pipaudit* ]]; then
  echo "[$R/$P] pip-audit"
  mkdir -p "$OUT/pip-audit"
  for f in $(git ls-files | grep -E '(^|/)requirements[^/]*\.txt$'); do
    n=$(echo "$f" | tr '/' '_')
    timeout 1200 pip-audit -r "$f" --progress-spinner off -f json -o "$OUT/pip-audit/$n.json" 2> "$OUT/pip-audit/$n.err"
    echo "  $f exit $?"
  done
fi

if [[ $TOOLS == *trivy* ]]; then
  echo "[$R/$P] trivy fs (vuln, misconfig, secret)"
  # --offline-scan: no Maven Central lookups (a pom.xml in civil-buddy-sme got the scan rate-limited)
  trivy fs --quiet --offline-scan --scanners vuln,misconfig,secret --skip-dirs frontend/node_modules --format json -o "$OUT/trivy-fs.json" . 2> "$OUT/trivy-fs.err"
  echo "trivy exit $?"
fi

if [[ $TOOLS == *gitleaks* ]]; then
  echo "[$R/$P] gitleaks (full history, redacted)"
  gitleaks git . --redact --no-banner --report-format json --report-path "$OUT/gitleaks.json" > "$OUT/gitleaks.log" 2>&1
  echo "gitleaks exit $?"
fi
