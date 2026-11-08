"""Check that the numbers in README.md and findings/ match results/counts.json and the cited commits.

usage: python scripts/verify_readme.py [--root DIR] [--online]

Offline (default):
  * every cell of the four "Scanner | Before | After" tables equals results/counts.json;
  * the "N commits" column of the first table equals the number of SHAs in the remediation table;
  * the last remediation commit of each fixed repository is the "after" commit in results/scanned_commits.json,
    and results/raw/<repo>/<phase>/meta.json records the same commits;
  * the numbers quoted in the prose ("179 fixable", "4 hits", ...) and the Semgrep "(xN)" tallies in findings/;
  * no tracked text names a local machine path.
--online also asks the GitHub API that every cited SHA is on its repository's default branch
(uses GITHUB_TOKEN if set). Exit 0 when everything holds, 1 otherwise.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

OWNER = "LUOaini1213"
SEV = [("Critical", "C"), ("High", "H"), ("Medium", "M"), ("Low", "L"), ("Unknown", "Unknown"), ("Info", "Info")]
ROWS = {
    "Semgrep (SAST)": "semgrep",
    "pip-audit (unique vulns)": "pip-audit",
    "npm audit": "npm-audit",
    "Trivy fs: dependency CVEs": "trivy-fs-vuln",
    "Trivy fs: Dockerfile/IaC misconfig": "trivy-misconfig",
    "Trivy fs: secrets": "trivy-secret",
    "gitleaks (full history)": "gitleaks",
    "ZAP baseline (web) (alert types)": "zap-web",
    "ZAP API scan (alert types)": "zap-api",
    "ZAP baseline (unauth) (alert types)": "zap-unauth",
    "ZAP baseline (auth) (alert types)": "zap-auth",
}
LOCAL_PATH = re.compile(r"[A-Za-z]:\\Users\\|[A-Za-z]:/Users/|/home/[a-z]|/mnt/[a-z]/|\\\\wsl")


def fmt(counts, key):
    if key == "pip-audit":
        return str(counts["n"])
    if not counts:
        return "0"
    return ", ".join(f"{counts[k]} {abbr}" for k, abbr in SEV if counts.get(k))


def row_key(label):
    m = re.fullmatch(r"Trivy image `([\w-]+)`: (all|fixable)", label)
    if m:
        return f"trivy-image-{m.group(1)}" + ("-fixable" if m.group(2) == "fixable" else "")
    return ROWS.get(label)


def check_tables(readme, counts, errors):
    cells = 0
    sections = re.split(r"^### ", readme, flags=re.M)[1:]
    seen = set()
    for sec in sections:
        repo = sec.split("\n", 1)[0].strip()
        if repo not in counts:
            continue
        seen.add(repo)
        for line in sec.splitlines():
            parts = [p.strip() for p in line.strip().strip("|").split("|")]
            if len(parts) != 3 or parts[0] in ("Scanner", "---") or set(parts[0]) <= {"-"}:
                continue
            label, before, after = parts
            key = row_key(label)
            if key is None:
                errors.append(f"{repo}: unknown table row {label!r}")
                continue
            for phase, cell in (("before", before), ("after", after)):
                ph = counts[repo].get(phase)
                if ph is None:
                    if cell != "not re-run":
                        errors.append(f"{repo}/{phase} {label}: README {cell!r}, but no {phase} scan is recorded")
                    continue
                if key not in ph:
                    errors.append(f"{repo}/{phase} {label}: README {cell!r}, but counts.json has no {key}")
                    continue
                want = fmt(ph[key], key)
                cells += 1
                if cell != want:
                    errors.append(f"{repo}/{phase} {label}: README {cell!r} != counts.json {want!r}")
    for repo in counts:
        if repo not in seen:
            errors.append(f"no results table for {repo}")
    return cells


def remediation(readme):
    out = {}
    m = re.search(r"^## Remediation commits\n(.*?)(?=^## )", readme, flags=re.M | re.S)
    for line in (m.group(1) if m else "").splitlines():
        parts = [p.strip() for p in line.strip().strip("|").split("|")]
        if len(parts) == 2 and parts[0] not in ("Repository",) and not set(parts[0]) <= {"-"}:
            out[parts[0]] = re.findall(r"`([0-9a-f]{7,40})`", parts[1])
    return out


def check_commits(readme, scanned, root, errors):
    rem = remediation(readme)
    if not rem:
        errors.append("remediation table not found")
    for repo, n in re.findall(r"^\| \[([\w-]+)\]\([^)]*\) \|[^|]*\| yes, (\d+) commits \|", readme, flags=re.M):
        if len(rem.get(repo, [])) != int(n):
            errors.append(f"{repo}: first table says {n} commits, remediation table lists {len(rem.get(repo, []))}")
    for repo, shas in rem.items():
        after = scanned.get(repo, {}).get("after", "")
        if not shas or not after.startswith(shas[-1]):
            errors.append(f"{repo}: last remediation commit {shas[-1:]} is not the scanned 'after' commit {after[:7]}")
    for repo, phases in scanned.items():
        for phase, sha in phases.items():
            p = os.path.join(root, "results", "raw", repo, phase, "meta.json")
            try:
                with open(p, encoding="utf-8") as f:
                    head = json.load(f).get("head")
            except (OSError, ValueError):
                errors.append(f"missing {os.path.relpath(p, root)}")
                continue
            if head != sha:
                errors.append(f"{repo}/{phase}: raw meta head {head} != scanned_commits {sha}")
    return rem


def check_prose(readme, counts, rem, errors):
    geo, fm, cb = (counts["sg-transit-geo-assistant"], counts["fm-knowledge-assistant"], counts["civil-buddy-sme"])
    web_before = geo["before"]["trivy-image-web-fixable"]
    checks = [
        (r"web image went from (\d+) fixable vulnerabilities", sum(web_before.values())),
        (r"fixable vulnerabilities \((\d+) HIGH\)", web_before.get("High", 0)),
        (r"to (\d+) MEDIUM by moving", geo["after"]["trivy-image-web-fixable"].get("Medium", 0)),
        (r"medium-risk ZAP alerts on the geo page went from (\d+)", geo["before"]["zap-web"].get("Medium", 0)),
        (r"medium-risk ZAP alerts on the geo page went from \d+ to (\d+)", geo["after"]["zap-web"].get("Medium", 0)),
        (r"fm's (\w+) remaining\s+medium alerts", fm["after"]["zap-web"].get("Medium", 0)),
        (r"gitleaks found (\d+) hits", sum(sum(r["before"].get("gitleaks", {}).values()) for r in counts.values())),
        (r"\((\d+) in fm, \d+ in civil-buddy-sme\)", fm["before"]["gitleaks"].get("High", 0)),
        (r"\(\d+ in fm, (\d+) in civil-buddy-sme\)", cb["before"]["gitleaks"].get("High", 0)),
        (r"(\d+) HIGH in Debian packages", geo["after"]["trivy-image-api"].get("High", 0)),
        (r"and (\d+) `liblzma5` UNKNOWN", geo["after"]["trivy-image-api-fixable"].get("Unknown", 0)),
        (r"fixes pushed to (\w+) of them", len(rem)),
        (r"fixes pushed to \w+ of them \((\d+) commits\)", sum(len(v) for v in rem.values())),
        (r"the (\w+) public repositories of mine", len(counts)),
    ]
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}
    n = 0
    for pat, want in checks:
        found = list(re.finditer(pat, readme))
        if not found:
            errors.append(f"README: sentence not found for /{pat}/")
        for m in found:
            got = words.get(m.group(1), m.group(1))
            n += 1
            if int(got) != want:
                errors.append(f"README /{pat}/: says {m.group(1)}, results give {want}")
    # the 44 HIGH left in the API images have no fix: the fixable column must hold no HIGH
    if geo["after"]["trivy-image-api-fixable"].get("High") or fm["after"]["trivy-image-api-fixable"].get("High"):
        errors.append("README says the remaining API-image HIGHs have no fix, but counts.json lists fixable HIGH")
    return n


def check_findings(root, counts, errors):
    n = 0
    for name in sorted(os.listdir(os.path.join(root, "findings"))):
        repo = name[:-3]
        rules = counts.get(repo, {}).get("before", {}).get("semgrep_rules", {})
        with open(os.path.join(root, "findings", name), encoding="utf-8") as f:
            for line in f:
                cell = line.split("|")[2] if line.startswith("|") and line.count("|") > 3 else ""
                if "Semgrep" not in cell:
                    continue
                for rule, k in re.findall(r"`([\w*-]+)` \(x(\d+)", cell):
                    if rule.endswith("*"):
                        have = sum(v for r, v in rules.items() if r.startswith(rule[:-1]))
                    else:
                        have = rules.get(rule)
                    n += 1
                    if have != int(k):
                        errors.append(f"findings/{name}: `{rule}` (x{k}) but counts.json semgrep_rules has {have}")
    return n


def check_local_paths(root, errors):
    try:
        files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        files = []
    me = os.path.join("scripts", "verify_readme.py").replace(os.sep, "/")
    for rel in files:
        if rel == me or rel.startswith("tests/"):
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if LOCAL_PATH.search(line):
                        errors.append(f"{rel}:{i}: local machine path")
        except (UnicodeDecodeError, OSError):
            pass


def gh_get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def check_online(rem, scanned, errors):
    n = 0
    shas = {(repo, s) for repo, ss in rem.items() for s in ss}
    shas |= {(repo, s) for repo, ph in scanned.items() for s in ph.values()}
    branches = {}
    for repo, sha in sorted(shas):
        try:
            if repo not in branches:
                branches[repo] = gh_get(f"https://api.github.com/repos/{OWNER}/{repo}")["default_branch"]
            cmp = gh_get(f"https://api.github.com/repos/{OWNER}/{repo}/compare/{sha}...{branches[repo]}")
        except urllib.error.HTTPError as e:
            errors.append(f"{repo}@{sha}: GitHub API {e.code}")
            continue
        n += 1
        if cmp.get("status") not in ("ahead", "identical"):
            errors.append(f"{repo}@{sha}: not on {branches[repo]} (compare status {cmp.get('status')})")
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check README/findings numbers against results/.")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--online", action="store_true")
    a = ap.parse_args(argv)
    with open(os.path.join(a.root, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    with open(os.path.join(a.root, "results", "counts.json"), encoding="utf-8") as f:
        counts = json.load(f)
    with open(os.path.join(a.root, "results", "scanned_commits.json"), encoding="utf-8") as f:
        scanned = json.load(f)
    errors = []
    cells = check_tables(readme, counts, errors)
    rem = check_commits(readme, scanned, a.root, errors)
    prose = check_prose(readme, counts, rem, errors)
    tallies = check_findings(a.root, counts, errors)
    check_local_paths(a.root, errors)
    msg = f"{cells} table cells, {prose} prose numbers, {tallies} Semgrep tallies, " \
          f"{sum(len(v) for v in rem.values())} remediation SHAs"
    if a.online:
        msg += f", {check_online(rem, scanned, errors)} SHAs on their default branch"
    for e in errors:
        print("FAIL", e)
    print(("FAILED: " if errors else "ok: ") + msg)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
