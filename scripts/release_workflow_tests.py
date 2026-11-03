"""Verify release selection against the real Cargo workspace metadata."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

VERSION_CASES = [
    ("1.2.3", True),
    ("0.0.0", True),
    ("1.2.3-beta.1", True),
    ("1.2.3-0.alpha-1+build.001", True),
    ("1.2.3+001.build", True),
    ("1.2.3-01a", True),
    ("1.2.3-..", False),
    ("1.2.3-01", False),
    ("1.2.3-alpha..1", False),
    ("1.2.3-alpha.01", False),
    ("1.2.3+build..1", False),
    ("01.2.3", False),
    ("1.02.3", False),
    ("1.2.03", False),
    ("1.2.3-", False),
    ("1.2.3+", False),
    ("1.2.3\n", False),
]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/release.yml").read_text()
        cls.metadata = subprocess.check_output(
            ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT
        )

    def test_release_uses_the_canonical_module_pipeline(self):
        """Every archive is built by the shared pipeline from the selected tag."""
        self.assertIn("tinyhumansai/.github/.github/workflows/module-release.yml@", self.workflow)
        self.assertIn("module-crate: tinywallet-module", self.workflow)
        self.assertNotIn("git push", self.workflow)
        self.assertNotIn("cargo package", self.workflow)

    def test_release_runs_only_the_main_tag_path(self):
        """Releases come only from official main: no reviewed-epic mode remains."""
        inputs = self.workflow.split("    inputs:\n", 1)[1].split("  push:\n", 1)[0]
        self.assertEqual(re.findall(r"(?m)^      (\w+):$", inputs), ["tag"])
        jobs = re.findall(r"(?m)^  ([\w-]+):$", self.workflow.split("\njobs:\n", 1)[1])
        self.assertEqual(jobs, ["resolve", "module-release"])
        for epic_only in ("reviewed-epic", "reviewed_pr", "inputs.mode", "epic/"):
            self.assertNotIn(epic_only, self.workflow)
        self.assertEqual(self.workflow.count("uses: tinyhumansai/.github/"), 1)

    def test_module_build_accepts_versioned_host_labels_without_paths(self):
        result = subprocess.run(
            [
                "bash",
                str(ROOT / "scripts/build-module.sh"),
                "--crate",
                "tinywallet-module",
                "--version",
                "0.10.0",
                "--target",
                "unsupported-target",
                "--host",
                "ubuntu-22.04-x86_64",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported module target", result.stderr)

        unsafe_host = subprocess.run(
            [
                "bash",
                str(ROOT / "scripts/build-module.sh"),
                "--crate",
                "tinywallet-module",
                "--version",
                "0.10.0",
                "--target",
                "unsupported-target",
                "--host",
                "../escape",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(unsafe_host.returncode, 2)
        self.assertIn("usage:", unsafe_host.stderr)

    def test_arch_release_install_disables_unsupported_container_sandbox(self):
        script = (ROOT / "scripts/build-module-in-distro.sh").read_text()
        self.assertRegex(script, r"pacman -Syu --noconfirm --disable-sandbox\b")

    def test_distro_container_script_parses_as_bash(self):
        for script in (
            ROOT / "scripts/test-distro.sh",
            ROOT / "scripts/build-module-in-distro.sh",
        ):
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["bash", "-n", str(script)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_distro_runner_invokes_the_mounted_build_script(self):
        target = ROOT / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="release-workflow-test-", dir=target) as scratch:
            scratch_path = Path(scratch)
            fake_bin = scratch_path / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import subprocess, sys\n"
                "expected_command = ['bash', '/workspace/scripts/build-module-in-distro.sh']\n"
                "args = sys.argv[1:]\n"
                f"volume_ok = len(args) > 2 and args[args.index('--volume') + 1] == '{ROOT}:/workspace'\n"
                "if not volume_ok or args[-2:] != expected_command:\n"
                "    print(f'unexpected container command: {args}', file=sys.stderr)\n"
                "    raise SystemExit(1)\n"
                f"raise SystemExit(subprocess.call(['bash', '-n', {str(ROOT / 'scripts/build-module-in-distro.sh')!r}]))\n"
            )
            docker.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts/test-distro.sh"),
                    "fedora:43@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42",
                    "--crate",
                    "tinywallet-module",
                    "--version",
                    "0.13.0",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--host",
                    "fedora-43-x86_64",
                    "--output-dir",
                    f"target/{scratch_path.name}/release-assets",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_module_verification_canonicalizes_a_symlinked_temp_root(self):
        target = ROOT / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="release-workflow-test-", dir=target) as scratch:
            scratch_path = Path(scratch)
            physical_tmp = scratch_path / "physical-tmp"
            physical_tmp.mkdir()
            alias_tmp = scratch_path / "tmp-alias"
            alias_tmp.symlink_to(physical_tmp, target_is_directory=True)

            archive = scratch_path / "tinywallet-module-test.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, contents in (
                    ("modules.toml", b'"libtinywallet_module.so" = "fixture-hash"\n'),
                    ("libtinywallet_module.so", b"fixture-library"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(contents)
                    bundle.addfile(info, io.BytesIO(contents))

            fake_bin = scratch_path / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "path = os.environ['TINYWALLET_TEST_MODULE']\n"
                "resolved = os.path.realpath(path)\n"
                "if path != resolved:\n"
                "    print(f'noncanonical module path: {path} -> {resolved}', file=sys.stderr)\n"
                "    raise SystemExit(1)\n"
            )
            cargo.chmod(0o755)

            env = os.environ.copy()
            env["TMPDIR"] = str(alias_tmp)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/verify-module.sh"), "--archive", str(archive)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_module_build_validates_semver_before_building(self):
        """Packaging rejects malformed versions before invoking Cargo."""
        for version, valid in VERSION_CASES:
            with self.subTest(version=version):
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/build-module.sh"),
                     "--crate", "tinywallet-module", "--version", version,
                     "--target", "unsupported-target", "--host", "test-host"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("unsupported module target" if valid else "usage:", result.stderr)

    def test_powershell_version_pattern_validates_complete_semver(self):
        """The Windows packaging guard uses the same SemVer rules."""
        script = (ROOT / "scripts/build-module.ps1").read_text()
        pattern = re.search(r"\$Version -notmatch '([^']+)'", script).group(1)
        self.assertTrue(pattern.endswith(r"\z"), ".NET must reject trailing newlines")
        # Python's fullmatch models the strict end anchor used by .NET.
        pattern = pattern.removesuffix(r"\z")
        for version, valid in VERSION_CASES:
            with self.subTest(version=version):
                self.assertEqual(re.fullmatch(pattern, version) is not None, valid)

    def test_resolve_step_validates_tag_format_and_outputs(self):
        """Tag resolution rejects invalid refs and passes valid version tags through."""
        script = self.workflow.split("        run: |\n", 1)[1].split("  module-release:", 1)[0]
        script = "\n".join(line[10:] for line in script.splitlines())
        with tempfile.TemporaryDirectory() as directory:
            for tag, valid in [("v" + version, valid) for version, valid in VERSION_CASES] + [
                ("main", False), ("v1.0.0; echo injected", False)
            ]:
                output = Path(directory) / "output"
                output.write_text("")
                result = subprocess.run(["bash", "-c", script],
                    env=dict(os.environ, TAG=tag, GITHUB_OUTPUT=str(output)), capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, (tag, result.stderr))
                if valid:
                    self.assertEqual(output.read_text(), "tag="+tag+"\nversion="+tag[1:]+"\n")
                else:
                    self.assertEqual(output.read_text(), "")

if __name__ == "__main__":
    unittest.main()
