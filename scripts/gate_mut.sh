#!/bin/bash
# Check that the CI gates fail on known-bad input (the gates are only evidence if they can fail).
export PATH=$HOME/.local/bin:$PATH SEMGREP_SEND_METRICS=off
TRIVY=aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
cd ${WORK:-$HOME/sec}/_before_geo
docker run --rm -v "$PWD:/src" -w /src "$TRIVY" fs --quiet --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --skip-dirs frontend/node_modules . > /dev/null 2>&1
echo "trivy gate on pre-fix geo (root nginx image): exit $? (expect 1)"
cd ${WORK:-$HOME/sec}/sg-transit-geo-assistant
semgrep scan --metrics=off --disable-version-check --error --severity ERROR --config p/python -q backend/app/build.py > /dev/null 2>&1
echo "semgrep gate on geo without the documented exclusion: exit $? (expect 1)"
docker run --rm -v "${WORK:-$HOME/sec}/fm-knowledge-assistant:/repo" zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f git /repo --redact --no-banner --config /dev/null > /dev/null 2>&1
echo "gitleaks gate on fm with an empty config (no rules): exit $? (sanity, expect 0)"
T=$(mktemp -d); cp -r ${WORK:-$HOME/sec}/fm-knowledge-assistant/.gitleaks.toml "$T"/; git -C "$T" init -q; printf 'aws_secret = "AKIAZ7Q4XN2LP5RT3WVY"\n' > "$T/creds.txt"; git -C "$T" -c user.name=t -c user.email=t@t add -A; git -C "$T" -c user.name=t -c user.email=t@t commit -qm t
docker run --rm -v "$T:/repo" zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f git /repo --redact --no-banner > /dev/null 2>&1
echo "gitleaks gate with fm's .gitleaks.toml on a planted AWS key id: exit $? (expect 1)"
rm -rf "$T"
