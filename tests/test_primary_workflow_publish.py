"""Exercise the actual CI publisher against a disposable local Git origin."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/build.yml"
OUTPUTS = ("qualified-all.txt", "best20.txt", "best50.txt", "best100.txt", "status.json", "history.json")


def publication_shell():
    # Read this exact literal run block without requiring an undeclared YAML
    # package in the CI Python environment. A structural change must fail loud.
    lines = WORKFLOW.read_text().splitlines()
    starts = [index for index, line in enumerate(lines) if line == "      - name: Publish"]
    if len(starts) != 1:
        raise AssertionError("Expected exactly one Publish workflow step")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith("      - name:")), len(lines))
    block = lines[start:end]
    offsets = [index for index, line in enumerate(block) if line == "        run: |"]
    if len(offsets) != 1:
        raise AssertionError("Publish must expose one literal shell block")
    body = block[offsets[0] + 1:]
    if not body or any(line.strip() and not line.startswith("          ") for line in body):
        raise AssertionError("Unexpected Publish shell indentation")
    return textwrap.dedent("\n".join(body)) + "\n"


class PrimaryWorkflowPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="bestlocal-ci-publish-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo, self.remote = self.root / "build", self.root / "origin.git"
        self.repo.mkdir()
        self.env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull}
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main")
        self.identity(self.repo)
        for name, text in {"scripts/build.py": "# baseline implementation\n", "config.json": "{}\n",
                           "README.md": "baseline documentation\n", "docs/existing.md": "baseline guide\n",
                           "output/best-local.txt": "preserved primary regional subscription\n",
                           "output/best-local-Serbia.txt": "preserved Serbia regional subscription\n"}.items():
            self.write(self.repo, name, text)
        for name in OUTPUTS:
            self.write(self.repo, "output/" + name, "old " + name + "\n")
        self.git("add", ".")
        self.git("commit", "-m", "fixture baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "HEAD:main")
        self.actor = self.root / "concurrent"
        self.git("clone", "--quiet", "--branch", "main", str(self.remote), str(self.actor))
        self.identity(self.actor)
        # The build step has produced these files but has not committed them.
        links = [f"vless://00000000-0000-4000-8000-{index:012d}@192.0.2.{index}:443?security=tls#fixture-{index}"
                 for index in range(1, 51)]
        self.generated = {
            "qualified-all.txt": "\n".join(links) + "\n",
            "best20.txt": "\n".join(links[:20]) + "\n",
            "best50.txt": "\n".join(links) + "\n",
            "best100.txt": "\n".join(links) + "\n",
            "status.json": json.dumps({"generated_at": 100, "published": {"best50": 50}}) + "\n",
            "history.json": json.dumps({"fixture": "new generated history"}) + "\n",
        }
        for name, text in self.generated.items():
            self.write(self.repo, "output/" + name, text)

    def git(self, *arguments, cwd=None):
        return subprocess.check_output(["git", *arguments], cwd=cwd or self.repo,
                                       env=self.env, text=True, stderr=subprocess.DEVNULL).strip()

    def identity(self, directory):
        self.git("config", "user.name", "Controlled fixture", cwd=directory)
        self.git("config", "user.email", "fixture@example.invalid", cwd=directory)
        self.git("config", "commit.gpgsign", "false", cwd=directory)

    @staticmethod
    def write(directory, name, text):
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def advance(self, files, *, push=True):
        for name, text in files.items():
            self.write(self.actor, name, text)
        self.git("add", ".", cwd=self.actor)
        self.git("commit", "-m", "fixture concurrent update", cwd=self.actor)
        if push:
            self.git("push", "origin", "HEAD:main", cwd=self.actor)
        return self.git("rev-parse", "HEAD", cwd=self.actor)

    def run_publisher(self, *, advance_at_push=False):
        shell = self.root / "publish.sh"
        shell.write_text(publication_shell())
        # No network or waiting: only the retry sleep is accelerated. The
        # production shell, Git operations and push conflicts are exercised.
        setup = 'sleep() { :; }; export -f sleep; '
        if advance_at_push:
            # Inject a genuine remote writer between the shell's last fetch and
            # first push. All publication/rebase code remains the actual workflow.
            setup += '''git() {
                if [ "$1" = push ] && [ ! -f "$CONTROLLED_RACE_MARKER" ]; then
                    touch "$CONTROLLED_RACE_MARKER"
                    command git -C "$CONTROLLED_RACE_ACTOR" push origin HEAD:main || return $?
                    return 1
                fi
                command git "$@"
            }; export -f git; '''
        env = {**self.env, "CONTROLLED_RACE_MARKER": str(self.root / "push-race"),
               "CONTROLLED_RACE_ACTOR": str(self.actor)}
        result = subprocess.run(["bash", "-c", setup + 'source "$1"',
                                 "controlled-publisher", str(shell)], cwd=self.repo, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def remote_text(self, path):
        return subprocess.check_output(["git", "--git-dir", str(self.remote), "show", "main:" + path],
                                       env=self.env, text=True)

    def remote_head(self):
        return self.git("--git-dir", str(self.remote), "rev-parse", "main")

    def assert_generated(self):
        for name, text in self.generated.items():
            self.assertEqual(self.remote_text("output/" + name), text)
        self.assertEqual(len(self.remote_text("output/best50.txt").splitlines()), 50)
        self.assertEqual(self.remote_text("output/best-local.txt"), "preserved primary regional subscription\n")
        self.assertEqual(self.remote_text("output/best-local-Serbia.txt"), "preserved Serbia regional subscription\n")

    def test_unchanged_inputs_publish_exactly_the_generated_outputs(self):
        self.run_publisher()
        self.assert_generated()
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "main^"), self.base)

    def test_documentation_advance_preserves_new_docs_and_publishes_outputs(self):
        concurrent = self.advance({"README.md": "new readme\n", "docs/new-guide.md": "new operational guide\n"})
        self.run_publisher()
        self.assert_generated()
        self.assertEqual(self.remote_text("README.md"), "new readme\n")
        self.assertEqual(self.remote_text("docs/new-guide.md"), "new operational guide\n")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "main^"), concurrent)

    def test_code_advance_withholds_generated_outputs(self):
        concurrent = self.advance({"scripts/build.py": "# changed validation implementation\n"})
        self.run_publisher()
        self.assertEqual(self.remote_head(), concurrent)
        self.assertEqual(self.remote_text("output/best50.txt"), "old best50.txt\n")

    def test_docs_racing_with_first_push_are_preserved_on_retry(self):
        concurrent = self.advance({"docs/race.md": "documentation during push\n"}, push=False)
        self.run_publisher(advance_at_push=True)
        self.assert_generated()
        self.assertEqual(self.remote_text("docs/race.md"), "documentation during push\n")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "main^"), concurrent)

    def test_code_racing_with_first_push_withholds_older_validation(self):
        concurrent = self.advance({"config.json": '{"changed_validation_policy":true}\n'}, push=False)
        self.run_publisher(advance_at_push=True)
        self.assertEqual(self.remote_head(), concurrent)
        self.assertEqual(self.remote_text("output/best50.txt"), "old best50.txt\n")
        self.assertEqual(self.remote_text("config.json"), '{"changed_validation_policy":true}\n')

    def test_concurrent_output_advance_cannot_be_replaced_by_older_build(self):
        concurrent = self.advance({"output/best50.txt": "newer concurrent pool\n"})
        self.run_publisher()
        self.assertEqual(self.remote_head(), concurrent)
        self.assertEqual(self.remote_text("output/best50.txt"), "newer concurrent pool\n")

    def test_transient_push_failure_retries_the_same_validated_outputs(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\nif [ ! -f controlled-first-push-rejected ]; then\n"
                        "  touch controlled-first-push-rejected\n  exit 1\nfi\nexit 0\n")
        hook.chmod(0o700)
        self.run_publisher()
        self.assertTrue((self.remote / "controlled-first-push-rejected").exists())
        self.assert_generated()


if __name__ == "__main__":
    unittest.main()
