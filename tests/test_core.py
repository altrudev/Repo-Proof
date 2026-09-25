import subprocess
import tempfile
import unittest
from pathlib import Path

from repoproof.core import current_report, load_config, transition

class RepoProofTests(unittest.TestCase):
    def git(self, repo, *args):
        subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True)

    def make_repo(self):
        td = tempfile.TemporaryDirectory()
        repo = Path(td.name)
        self.git(repo, "init")
        self.git(repo, "config", "user.email", "test@example.com")
        self.git(repo, "config", "user.name", "RepoProof Test")
        (repo / "LICENSE").write_text("evaluation only\n")
        (repo / "app.py").write_text("print('hello')\n")
        (repo / "repoproof.toml").write_text("""[[claims]]
id="license"
statement="license exists"
kind="path_exists"
path="LICENSE"

[boundary.network]
allow=[]

[boundary.process]
spawn=false

[[invariants]]
id="deps"
statement="dependencies unchanged"
kind="dependencies_unchanged"
""")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", "base")
        return td, repo

    def test_clean_check_verifies(self):
        td, repo = self.make_repo()
        try:
            report = current_report(repo, load_config(repo))
            self.assertEqual(report["result"], "VERIFIED")
        finally:
            td.cleanup()

    def test_network_expansion_is_detected(self):
        td, repo = self.make_repo()
        try:
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            (repo / "app.py").write_text('url="https://api.example.com/v1"\n')
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "network expansion")
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            report = transition(repo, load_config(repo), base, head)
            self.assertEqual(report["result"], "REVIEW_REQUIRED")
            self.assertTrue(any(f["id"] == "network.expansion" and f["status"] == "CONTRADICTED" for f in report["findings"]))
        finally:
            td.cleanup()

    def test_dependency_change_is_detected(self):
        td, repo = self.make_repo()
        try:
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            (repo / "requirements.txt").write_text("requests==2.32.0\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "add dependency")
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            report = transition(repo, load_config(repo), base, head)
            self.assertTrue(any(f["id"] == "deps" and f["status"] == "CONTRADICTED" for f in report["findings"]))
        finally:
            td.cleanup()

if __name__ == "__main__":
    unittest.main()
