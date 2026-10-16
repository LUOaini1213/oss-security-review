#!/bin/bash
# usage: img.sh <repo> <phase> <label> <image>   trivy image scan (OS + language packages, secrets)
export PATH=$HOME/.local/bin:$PATH
OUT=${WORK:-$HOME/sec}/_results/$1/$2
mkdir -p "$OUT"
docker image inspect "$4" --format '{{.Id}} {{.Size}}' > "$OUT/image-$3.id"
trivy image --quiet --scanners vuln,secret --format json -o "$OUT/trivy-image-$3.json" "$4" 2> "$OUT/trivy-image-$3.err"
echo "trivy image $3 exit $?"
python3 - "$OUT/trivy-image-$3.json" <<'PY'
import json, sys
from collections import Counter
d = json.load(open(sys.argv[1]))
c = Counter(); fixable = Counter()
for r in d.get("Results") or []:
    for v in r.get("Vulnerabilities") or []:
        c[v["Severity"]] += 1
        if v.get("FixedVersion"): fixable[v["Severity"]] += 1
print("  all", dict(c), "fixable", dict(fixable), "os", (d.get("Metadata") or {}).get("OS"))
PY
