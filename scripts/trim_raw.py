"""Copy the scanner reports into results/raw/ with only the fields the counts and the triage need.

usage: python scripts/trim_raw.py [--src DIR] [--dst DIR]

--src defaults to ${WORK:-$HOME/sec}/_results (where secscan.sh, img.sh and seczap.sh write);
--dst defaults to results/raw in this repository.

What is dropped, and why: secret values and matched text (gitleaks Secret/Match, Trivy secret Match/Code,
Semgrep `lines`), commit author names and e-mails, long advisory descriptions and references, and URL query
strings in ZAP instances. What is kept is enough for scripts/counts.py to rebuild results/counts.json
byte for byte (`python scripts/counts.py --base results/raw --check`) and for a reader to see which rule fired
where, on which package and version, with which fix.
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def dump(obj, p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def pick(d, keys):
    return {k: d[k] for k in keys if k in d}


def semgrep(d):
    return {"version": d.get("version"),
            "results": [{"check_id": r["check_id"], "path": r["path"],
                         "start": {"line": r["start"]["line"]},
                         "extra": {"severity": r["extra"]["severity"]}} for r in d["results"]]}


def pip_audit(d):
    return {"dependencies": [{"name": x["name"], "version": x.get("version"),
                              "vulns": [pick(v, ("id", "fix_versions", "aliases")) for v in x.get("vulns", [])]}
                             for x in d.get("dependencies", []) if x.get("vulns")]}


def npm_audit(d):
    return {"metadata": {"vulnerabilities": d.get("metadata", {}).get("vulnerabilities", {})},
            "vulnerabilities": {k: pick(v, ("name", "severity", "isDirect", "range", "fixAvailable"))
                                for k, v in (d.get("vulnerabilities") or {}).items()}}


VULN_KEYS = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Status")


def trivy(d):
    out = {"ArtifactName": d.get("ArtifactName"), "Metadata": pick(d.get("Metadata") or {}, ("OS",)),
           "Results": []}
    for r in d.get("Results") or []:
        rr = pick(r, ("Target", "Class", "Type"))
        if r.get("Vulnerabilities"):
            rr["Vulnerabilities"] = [pick(v, VULN_KEYS) for v in r["Vulnerabilities"]]
        mis = [pick(m, ("ID", "Title", "Severity", "Status")) for m in r.get("Misconfigurations") or []
               if m.get("Status") == "FAIL"]
        if mis:
            rr["Misconfigurations"] = mis
        if r.get("Secrets"):
            rr["Secrets"] = [pick(s, ("RuleID", "Severity", "StartLine")) for s in r["Secrets"]]
        if len(rr) > 3:
            out["Results"].append(rr)
    return out


def gitleaks(d):
    return [pick(x, ("RuleID", "File", "StartLine", "Commit")) for x in d]


def zap(d):
    sites = []
    for s in d.get("site", []):
        alerts = [{"pluginid": a["pluginid"], "name": a["name"], "riskcode": a["riskcode"],
                   "instances": [{"method": i.get("method"), "uri": i.get("uri", "").split("?")[0]}
                                 for i in a.get("instances", [])]} for a in s.get("alerts", [])]
        sites.append({"@name": s.get("@name"), "alerts": alerts})
    return {"@version": d.get("@version"), "@generated": d.get("@generated"), "site": sites}


def read_text(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def trim_phase(src, dst):
    n = 0
    meta = {"head": read_text(os.path.join(src, "HEAD.txt")),
            "scanned_at": read_text(os.path.join(src, "scanned_at.txt")), "images": {}}
    for p in sorted(glob.glob(os.path.join(src, "image-*.id"))):
        img_id, _, size = (read_text(p) or "").partition(" ")
        meta["images"][os.path.basename(p)[len("image-"):-3]] = {"id": img_id, "bytes": int(size) if size else None}
    dump(meta, os.path.join(dst, "meta.json"))
    jobs = [("semgrep.json", semgrep), ("trivy-fs.json", trivy), ("gitleaks.json", gitleaks)]
    for name, fn in jobs:
        p = os.path.join(src, name)
        if os.path.exists(p):
            dump(fn(load(p)), os.path.join(dst, name)); n += 1
    for pat, fn in (("pip-audit/*.json", pip_audit), ("npm-audit*.json", npm_audit),
                    ("trivy-image-*.json", trivy), ("zap-*.json", zap)):
        for p in sorted(glob.glob(os.path.join(src, pat))):
            rel = os.path.relpath(p, src)
            dump(fn(load(p)), os.path.join(dst, rel)); n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", default=os.path.join(os.environ.get("WORK") or os.path.expanduser("~/sec"), "_results"))
    ap.add_argument("--dst", default=os.path.join(ROOT, "results", "raw"))
    a = ap.parse_args(argv)
    total = 0
    for repo in sorted(os.listdir(a.src)) if os.path.isdir(a.src) else []:
        if repo.startswith("_"):
            continue
        for phase in ("before", "after"):
            d = os.path.join(a.src, repo, phase)
            if os.path.isdir(d):
                k = trim_phase(d, os.path.join(a.dst, repo, phase))
                print(f"{repo}/{phase}: {k} reports")
                total += k
    if not total:
        print(f"no <repo>/<before|after>/ reports under {a.src}; nothing written", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
