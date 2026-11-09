"""The repository's own checks must pass on the committed files and fail when what they guard is broken."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = [sys.executable, "-I"]


def run(*args, cwd=ROOT):
    return subprocess.run(PY + list(args), cwd=cwd, capture_output=True, text=True, encoding="utf-8")


class Copy:
    """A throwaway copy of the repository (README, findings, results, scripts) that a test may break."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp()
        for name in ("README.md", "findings", "results", "scripts"):
            src = os.path.join(ROOT, name)
            dst = os.path.join(self.dir, name)
            (shutil.copytree if os.path.isdir(src) else shutil.copy)(src, dst)
        return self.dir

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)


def edit(path, old, new, count=1):
    with open(path, encoding="utf-8") as f:
        s = f.read()
    assert old in s, f"{old!r} not in {path}"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(s.replace(old, new, count))


class CountsTest(unittest.TestCase):
    def test_rebuilds_committed_counts_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "counts.json")
            r = run("scripts/counts.py", "--base", "results/raw", "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, "rb") as a, open(os.path.join(ROOT, "results", "counts.json"), "rb") as b:
                self.assertEqual(a.read().replace(b"\r\n", b"\n"), b.read().replace(b"\r\n", b"\n"))

    def test_check_passes(self):
        r = run("scripts/counts.py", "--base", "results/raw", "--check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_empty_base_exits_nonzero_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "counts.json")
            r = run("scripts/counts.py", "--base", os.path.join(t, "nothing"), "--out", out)
            self.assertEqual(r.returncode, 2)
            self.assertFalse(os.path.exists(out))

    def test_default_does_not_touch_committed_counts(self):
        path = os.path.join(ROOT, "results", "counts.json")
        with open(path, "rb") as f:
            before = f.read()
        env = dict(os.environ, WORK=tempfile.mkdtemp())
        try:
            r = subprocess.run(PY + ["scripts/counts.py"], cwd=ROOT, capture_output=True, text=True, env=env)
        finally:
            shutil.rmtree(env["WORK"], ignore_errors=True)
        self.assertEqual(r.returncode, 2)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_check_fails_when_a_report_changes(self):
        with Copy() as d:
            p = os.path.join(d, "results", "raw", "sg-transit-geo-assistant", "after", "trivy-image-web.json")
            with open(p, encoding="utf-8") as f:
                rep = json.load(f)
            rep["Results"][0]["Vulnerabilities"].append(dict(rep["Results"][0]["Vulnerabilities"][0]))
            with open(p, "w", encoding="utf-8") as f:
                json.dump(rep, f)
            r = run(os.path.join(d, "scripts", "counts.py"), "--base", os.path.join(d, "results", "raw"),
                    "--out", os.path.join(d, "results", "counts.json"), "--check")
            self.assertEqual(r.returncode, 1, r.stdout)


class VerifyReadmeTest(unittest.TestCase):
    def verify(self, d):
        return run(os.path.join(d, "scripts", "verify_readme.py"), "--root", d)

    def test_passes(self):
        r = run("scripts/verify_readme.py")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("73 table cells", r.stdout)

    def test_mutations_fail(self):
        cases = [
            ("README.md", "| Semgrep (SAST) | 22 H, 27 M | 22 H, 22 M |", "| Semgrep (SAST) | 22 H, 26 M | 22 H, 22 M |"),
            ("README.md", "| Trivy image `web`: all | 44 H, 83 M, 50 L, 2 Unknown | 1 M |",
             "| Trivy image `web`: all | 44 H, 83 M, 50 L, 2 Unknown | 0 |"),
            ("README.md", "| ZAP baseline (auth) (alert types) | 3 M, 7 L, 4 Info | not re-run |",
             "| ZAP baseline (auth) (alert types) | 3 M, 7 L, 4 Info | 0 |"),
            ("README.md", "yes, 7 commits", "yes, 8 commits"),
            ("README.md", "`bda2f5d` security headers", "`bda2f5e` security headers"),
            ("README.md", "179 fixable vulnerabilities (44 HIGH) to 1 MEDIUM;", "180 fixable vulnerabilities (44 HIGH) to 1 MEDIUM;"),
            ("README.md", "gitleaks found 4 hits", "gitleaks found 5 hits"),
            ("README.md", "fixes pushed to three of them (17 commits)", "fixes pushed to three of them (18 commits)"),
            ("findings/civil-buddy-sme.md", "`dynamic-urllib-use-detected` (x24)", "`dynamic-urllib-use-detected` (x23)"),
            ("results/scanned_commits.json", '"after": "bda2f5d', '"after": "bda2f5e'),
            ("README.md", "## Residual risk", "Scans ran from C:\\Users\\someone\\sec.\n\n## Residual risk"),
        ]
        for rel, old, new in cases:
            with self.subTest(rel=rel, new=new), Copy() as d:
                subprocess.run(["git", "init", "-q"], cwd=d)
                subprocess.run(["git", "-c", "core.autocrlf=false", "add", "-A"], cwd=d)
                self.assertEqual(self.verify(d).returncode, 0, "copy must pass before the mutation")
                edit(os.path.join(d, rel), old, new)
                r = self.verify(d)
                self.assertEqual(r.returncode, 1, f"mutation survived: {new!r}\n{r.stdout}")


class TrimRawTest(unittest.TestCase):
    def test_drops_secrets_and_authors(self):
        with tempfile.TemporaryDirectory() as t:
            src = os.path.join(t, "src", "demo", "before")
            os.makedirs(src)
            with open(os.path.join(src, "gitleaks.json"), "w", encoding="utf-8") as f:
                json.dump([{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 3, "Commit": "abc",
                            "Secret": "SYNTHETIC-SECRET", "Match": "key=SYNTHETIC-SECRET",
                            "Author": "Someone", "Email": "someone@example.com"}], f)
            with open(os.path.join(src, "zap-web.json"), "w", encoding="utf-8") as f:
                json.dump({"site": [{"@name": "http://127.0.0.1:1", "alerts": [
                    {"pluginid": "1", "name": "x", "riskcode": "1", "desc": "long",
                     "instances": [{"uri": "http://127.0.0.1:1/?token=SYNTHETIC-SECRET", "method": "GET"}]}]}]}, f)
            dst = os.path.join(t, "dst")
            r = run("scripts/trim_raw.py", "--src", os.path.join(t, "src"), "--dst", dst)
            self.assertEqual(r.returncode, 0, r.stderr)
            text = ""
            for base, _, files in os.walk(dst):
                for name in files:
                    with open(os.path.join(base, name), encoding="utf-8") as f:
                        text += f.read()
            for leaked in ("SYNTHETIC-SECRET", "someone@example.com", "Someone"):
                self.assertNotIn(leaked, text)
            r = run("scripts/counts.py", "--base", dst, "--out", os.path.join(t, "c.json"))
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(t, "c.json"), encoding="utf-8") as f:
                c = json.load(f)["demo"]["before"]
            self.assertEqual(c["gitleaks"], {"High": 1})
            self.assertEqual(c["zap-web"], {"Low": 1})

    def test_empty_src_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as t:
            r = run("scripts/trim_raw.py", "--src", t, "--dst", os.path.join(t, "dst"))
            self.assertEqual(r.returncode, 2)

    def test_committed_raw_has_no_secret_fields(self):
        banned = ('"Secret"', '"Match"', '"Email"', '"Author"', '"lines"', '"Code"')
        for base, _, files in os.walk(os.path.join(ROOT, "results", "raw")):
            for name in files:
                with open(os.path.join(base, name), encoding="utf-8") as f:
                    s = f.read()
                for b in banned:
                    self.assertNotIn(b, s, os.path.join(base, name))


if __name__ == "__main__":
    unittest.main()
