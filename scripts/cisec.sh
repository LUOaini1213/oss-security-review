#!/bin/bash
# usage: cisec.sh <repo>   Replays the CI "security" job's gates on a fresh clone of the local repo HEAD.
export PATH=$HOME/.local/bin:$PATH SEMGREP_SEND_METRICS=off
R=$1
TRIVY=aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
GITLEAKS=zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
W=$(mktemp -d /tmp/cisec.XXXX)
git -c safe.directory='*' clone -q ${WORK:-$HOME/sec}/$R "$W/repo" && cd "$W/repo" || exit 1
echo "HEAD $(git log -1 --format='%h %s')"
docker run --rm -v "$PWD:/repo" "$GITLEAKS" git /repo --redact --no-banner > ../gl.log 2>&1; echo "gate gitleaks exit $? :: $(tail -1 ../gl.log)"
EXCL=()
case $R in
  sg-transit-geo-assistant) CFG="--config p/default --config p/owasp-top-ten --config p/python --config p/typescript --config p/dockerfile --config p/secrets"
     EXCL=(--exclude-rule python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query) ;;
  fm-knowledge-assistant) CFG="--config p/default --config p/owasp-top-ten --config p/python --config p/dockerfile --config p/secrets"
     EXCL=(--exclude-rule python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query) ;;
  *) CFG="--config p/default --config p/owasp-top-ten --config p/python --config p/secrets" ;;
esac
semgrep scan --metrics=off --disable-version-check --error --severity ERROR $CFG "${EXCL[@]}" -q > ../sg.log 2>&1; echo "gate semgrep exit $? :: $(grep -c 'rule' ../sg.log) lines mentioning rules"
docker run --rm -v "$PWD:/src" -w /src "$TRIVY" fs --quiet --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --skip-dirs frontend/node_modules . > ../tv.log 2>&1; echo "gate trivy-fs exit $?"
if [ -f frontend/package-lock.json ]; then echo "npm audit: run on Windows side"; fi
cd / && rm -rf "$W"
