"""Count scanner findings by severity for every repo/phase under _results; write counts.json and print a table.

Severity mapping: Semgrep ERROR/WARNING/INFO -> High/Medium/Low. Trivy and npm keep their own levels
(CRITICAL/HIGH/MEDIUM/LOW; npm moderate -> Medium). ZAP counts alert types by risk (High/Medium/Low/Info).
gitleaks has no severity: every hit is counted under High. pip-audit has no severity in its output: counted as 'n'.
"""
import glob
import json
import os
import sys
from collections import Counter

BASE = r"results"
SEM = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
TRI = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Unknown"}
ZAP = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}


def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def phase_counts(d):
    out = {}
    s = load(os.path.join(d, "semgrep.json"))
    if s is not None:
        out["semgrep"] = dict(Counter(SEM[r["extra"]["severity"]] for r in s["results"]))
        out["semgrep_rules"] = dict(Counter(r["check_id"].split(".")[-1] for r in s["results"]))
    pa = set()
    files = glob.glob(os.path.join(d, "pip-audit", "*.json"))
    for p in files:
        for dep in (load(p) or {}).get("dependencies", []):
            for v in dep.get("vulns", []):
                pa.add((dep["name"], dep["version"], v["id"]))
    if files:
        out["pip-audit"] = {"n": len(pa)}
    for p in glob.glob(os.path.join(d, "npm-audit*.json")):
        m = (load(p) or {}).get("metadata", {}).get("vulnerabilities", {})
        out["npm-audit"] = {k2: m.get(k1, 0) for k1, k2 in
                            [("critical", "Critical"), ("high", "High"), ("moderate", "Medium"), ("low", "Low")] if m.get(k1)}
    t = load(os.path.join(d, "trivy-fs.json"))
    if t is not None:
        vc, mc, sc = Counter(), Counter(), Counter()
        for r in t.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                vc[TRI[v["Severity"]]] += 1
            for m in r.get("Misconfigurations") or []:
                if m.get("Status") == "FAIL":
                    mc[TRI[m["Severity"]]] += 1
            for x in r.get("Secrets") or []:
                sc[TRI[x["Severity"]]] += 1
        out["trivy-fs-vuln"], out["trivy-misconfig"], out["trivy-secret"] = dict(vc), dict(mc), dict(sc)
    for p in sorted(glob.glob(os.path.join(d, "trivy-image-*.json"))):
        lab = os.path.basename(p)[len("trivy-image-"):-5]
        t = load(p) or {}
        allc, fix = Counter(), Counter()
        for r in t.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                allc[TRI[v["Severity"]]] += 1
                if v.get("FixedVersion"):
                    fix[TRI[v["Severity"]]] += 1
        out[f"trivy-image-{lab}"] = dict(allc)
        out[f"trivy-image-{lab}-fixable"] = dict(fix)
    g = load(os.path.join(d, "gitleaks.json"))
    if g is not None:
        out["gitleaks"] = {"High": len(g)} if g else {}
    for p in sorted(glob.glob(os.path.join(d, "zap-*.json"))):
        lab = os.path.basename(p)[4:-5]
        z = load(p) or {}
        c = Counter()
        names = []
        for site in z.get("site", []):
            for a in site.get("alerts", []):
                c[ZAP[str(a["riskcode"])]] += 1
                names.append(f'{ZAP[str(a["riskcode"])]}: {a["name"]} [{a["pluginid"]}] x{len(a["instances"])}')
        out[f"zap-{lab}"] = dict(c)
        out[f"zap-{lab}-alerts"] = sorted(names)
    return out


def main():
    allc = {}
    for repo in sorted(os.listdir(BASE)):
        if repo.startswith("_"):
            continue
        for phase in ("before", "after"):
            d = os.path.join(BASE, repo, phase)
            if os.path.isdir(d):
                allc.setdefault(repo, {})[phase] = phase_counts(d)
    with open(os.path.join(BASE, "counts.json"), "w", encoding="utf-8") as f:
        json.dump(allc, f, indent=1, sort_keys=True)
    for repo, ph in allc.items():
        print("=" * 20, repo)
        keys = sorted({k for p in ph.values() for k in p if not k.endswith(("-alerts", "_rules"))})
        for k in keys:
            print(f"  {k:28} before={ph.get('before', {}).get(k)}  after={ph.get('after', {}).get(k)}")


if __name__ == "__main__":
    main()
