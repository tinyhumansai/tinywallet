"""Guard native fixture staging, test cardinality, and client coverage scope."""

from pathlib import Path
import json
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_COUNTS = {
    "module_e2e": 2,
    "lifecycle_e2e": 1,
}
MODULE_TESTS = {
    "module_e2e.rs": (
        "refuses_a_confidential_call_to_an_unattested_module",
        "the_built_module_signs_every_chain_over_a_real_broker",
    ),
    "lifecycle_e2e.rs": ("the_built_module_signs_every_chain_over_a_real_broker",),
}


def _job_block(workflow, job_name):
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    return match.group(1) if match else ""


def _msrv_contract_issues(workflow):
    issues = []
    matrix_start = workflow.find("msrv-build-targets: |\n")
    matrix_end = workflow.find("      module-e2e-script:", matrix_start)
    if matrix_start < 0 or matrix_end < 0:
        return ["shared MSRV package matrix is missing"]
    targets = json.loads(
        workflow[matrix_start:].split("|\n", 1)[1].split(
            "      module-e2e-script:", 1
        )[0]
    )

    bus_manifest = tomllib.loads((ROOT / "crates/tinywallet-bus/Cargo.toml").read_text())
    module_manifest = tomllib.loads((ROOT / "crates/tinywallet-module/Cargo.toml").read_text())
    bus_floor = bus_manifest["package"]["rust-version"]
    module_floor = module_manifest["package"]["rust-version"]
    if bus_floor != "1.88":
        issues.append("tinywallet-bus floor must match tinystoragedrivers-types Rust 1.88")
    if module_floor != "1.88":
        issues.append("tinywallet-module floor must match its Rust 1.88 runtime dependencies")

    bus_wire = any(
        target.get("packages") == ["tinywallet-bus"]
        and target.get("features") == ["wire"]
        and not target.get("all_features", False)
        for target in targets
    )
    if not bus_wire:
        issues.append("shared MSRV matrix must build the bus wire feature at Rust 1.88")
    bus_all_features = any(
        target.get("packages") == ["tinywallet-bus"]
        and target.get("all_targets", False)
        and target.get("all_features", False)
        for target in targets
    )
    if not bus_all_features:
        issues.append("shared MSRV matrix must build bus storage vocabulary all-features at Rust 1.88")
    module_matrix = any(
        target.get("packages") == ["tinywallet-module"]
        and target.get("all_targets", False)
        and target.get("all_features", False)
        for target in targets
    )
    if not module_matrix:
        issues.append("shared MSRV matrix must build all module targets/features at its Rust 1.88 floor")

    ledger_job = _job_block(workflow, "wallet-ledger-msrv")
    if "toolchain: '1.88.0'" not in ledger_job:
        issues.append("x402 ledger feature job must use Rust 1.88.0")
    if "cargo test --locked -p tinywallet-x402 --features ledger" not in ledger_job:
        issues.append("Rust 1.88 ledger job must test the x402 ledger consumer")
    if "tinywallet-bus --all-targets --all-features" in ledger_job:
        issues.append("bus all-features must stay in the bus package's Rust 1.88 matrix target")

    proof_job = _job_block(workflow, "wallet-storage-contract")
    if "toolchain: '1.88.0'" not in proof_job or (
        "cargo test --locked --manifest-path proof-workspaces/storage-contract/Cargo.toml"
        not in proof_job
    ):
        issues.append("storage collection contract proof must be tested on Rust 1.88")

    bus_docs = (ROOT / "crates/tinywallet-bus/README.md").read_text()
    bus_manifest_text = (ROOT / "crates/tinywallet-bus/Cargo.toml").read_text()
    x402_manifest_text = (ROOT / "crates/tinywallet-x402/Cargo.toml").read_text()
    if "Rust 1.88" not in bus_docs or "tinystoragedrivers-types" in bus_manifest_text:
        issues.append("bus docs and manifest must keep portable collection declarations free of storage-driver dependencies at Rust 1.88")
    if not all(word in x402_manifest_text for word in ("1.88", "ledger", "pay", "tools")):
        issues.append("x402 manifest must document the Rust 1.88 ledger/pay/tools feature floor")
    return issues


class NativeE2ETopologyTests(unittest.TestCase):
    def test_msrv_matrix_tracks_the_tsd_v2_bus_and_module_floors(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(_msrv_contract_issues(workflow), [])

    def test_msrv_contract_requires_bus_storage_vocabulary_allfeatures_at_its_1_88_floor(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        bus_all_features = '{"packages":["tinywallet-bus"],"all_targets":true,"all_features":true},'
        self.assertIn(bus_all_features, workflow)
        mutated = workflow.replace(bus_all_features, "", 1)
        self.assertIn(
            "shared MSRV matrix must build bus storage vocabulary all-features at Rust 1.88",
            _msrv_contract_issues(mutated),
        )

    def test_msrv_contract_rejects_lowering_the_x402_ledger_job_toolchain(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        ledger_job = _job_block(workflow, "wallet-ledger-msrv")
        self.assertTrue(ledger_job)
        mutated_job = ledger_job.replace("toolchain: '1.88.0'", "toolchain: '1.85.1'", 1)
        self.assertNotEqual(ledger_job, mutated_job)
        mutated = workflow.replace(ledger_job, mutated_job, 1)
        self.assertIn(
            "x402 ledger feature job must use Rust 1.88.0",
            _msrv_contract_issues(mutated),
        )

    def test_module_e2e_cases_are_present_and_run_against_the_built_artifact(self):
        for filename, names in MODULE_TESTS.items():
            source = (ROOT / "crates/tinywallet-module/tests" / filename).read_text()
            for name in names:
                self.assertRegex(source, rf"(?m)^async fn {re.escape(name)}\(")

        shell = (ROOT / "scripts/test-e2e.sh").read_text()
        self.assertEqual(shell.count("--test module_e2e"), 1)
        self.assertEqual(shell.count("--test lifecycle_e2e"), 1)
        self.assertIn("TINYWALLET_TEST_MODULE=", shell)
        self.assertIn("--package tinywallet-client", shell)
        for target in ("native_e2e", "attested_errors", "native_unattested"):
            self.assertIn(f"--test {target}", shell)
        self.assertIn("TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256=", shell)

        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("module-e2e-script: scripts/test-e2e.sh", ci)

    def test_feature_and_coverage_lanes_use_current_workspace_targets(self):
        feature_shell = (ROOT / "scripts/test-features.sh").read_text()
        self.assertIn("cargo test --locked --workspace", feature_shell)
        self.assertNotIn("--prepare-only", feature_shell)
        self.assertIn("--exclude tinywallet-client", feature_shell)
        self.assertIn("-p tinywallet-client --lib --all-features", feature_shell)
        self.assertIn("cargo test --locked --workspace --all-features", feature_shell)

        feature_windows = (ROOT / "scripts/test-features.ps1").read_text()
        self.assertNotIn("PrepareOnly", feature_windows)
        self.assertIn("cargo test --locked --workspace --all-features --exclude tinywallet-client", feature_windows)
        self.assertIn("cargo test --locked -p tinywallet-client --lib --all-features", feature_windows)

        coverage = (ROOT / "scripts/check-coverage.sh").read_text()
        self.assertNotIn("--prepare-only", coverage)
        self.assertIn("--exclude tinywallet-client", coverage)
        self.assertIn("cargo llvm-cov --workspace --exclude tinywallet-client --all-features --all-targets", coverage)

    def test_windows_archive_operand_is_local_not_a_drive_qualified_remote(self):
        powershell = (ROOT / "scripts/test-e2e.ps1").read_text()
        self.assertIn("Push-Location $target", powershell)
        self.assertIn("& cargo test @Arguments", powershell)
        self.assertIn("[string[]]$Arguments", powershell)
        self.assertIn("tar.exe -czf $archiveName -C 'tinywallet-client-e2e-cache' .", powershell)
        self.assertNotIn("tar.exe -czf $archivePath", powershell)

    def test_contributor_checklists_use_the_feature_runner(self):
        for filename in ("AGENTS.md", "CONTRIBUTING.md", "README.md", ".github/PULL_REQUEST_TEMPLATE.md"):
            source = (ROOT / filename).read_text()
            self.assertIn("scripts/test-features.sh", source)
            self.assertNotRegex(source, r"(?m)^cargo test --all-features\s*$")
        self.assertIn("scripts/test-features.ps1", (ROOT / "CONTRIBUTING.md").read_text())
        self.assertIn("scripts/test-features.ps1", (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text())


if __name__ == "__main__":
    unittest.main()
