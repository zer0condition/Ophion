"""Tests for the fixture-only EAC/EOS startup observation emulator.

These tests exercise hand-authored recorded fixtures. They are not EAC, EOS,
BattlEye, game, driver, or protected-process validation.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "lab"
sys.path.insert(0, str(LAB))

from eac_harness import (  # noqa: E402
    OBSERVATION_SCHEMA,
    OBSERVATION_SCHEMA_VERSION,
    FixtureSchemaError,
    StartupEmulator,
    load_recorded_fixture,
    validate_test_matrix,
)


class StartupHarnessFixtureTests(unittest.TestCase):
    def assert_fixture_finding(self, fixture_name: str, detector_id: str, classification: str) -> None:
        events = load_recorded_fixture(LAB / "fixtures" / fixture_name)
        findings = StartupEmulator().emulate(events)
        self.assertIn(
            (detector_id, classification),
            {(finding["detector_id"], finding["classification"]) for finding in findings},
        )

    def test_0xc5_cpuid_mismatch(self) -> None:
        self.assert_fixture_finding("hypervisor_cpuid_mismatch.jsonl", "hypervisor-cpuid-coherence", "fail")

    def test_synthetic_msr_direction_error(self) -> None:
        self.assert_fixture_finding("synthetic_msr_direction_error.jsonl", "synthetic-msr-direction", "fail")

    def test_kuser_qpc_nonmonotonicity(self) -> None:
        self.assert_fixture_finding("kuser_qpc_nonmonotonic.jsonl", "kuser-qpc-monotonicity", "fail")

    def test_stack_return_outside_known_image(self) -> None:
        self.assert_fixture_finding("stack_return_outside_image.jsonl", "stack-return-known-image", "fail")

    def test_unbacked_executable_allocation(self) -> None:
        self.assert_fixture_finding("unbacked_executable_allocation.jsonl", "unbacked-executable-allocation", "fail")

    def test_module_image_verification_mismatch(self) -> None:
        self.assert_fixture_finding("module_image_verification_mismatch.jsonl", "module-image-verification", "fail")

    def test_unknown_tpm_measured_boot_state(self) -> None:
        self.assert_fixture_finding("unknown_tpm_measured_boot.jsonl", "tpm-measured-boot-state", "inconclusive")

    def test_clean_mock_fixture_has_no_finding(self) -> None:
        events = load_recorded_fixture(LAB / "fixtures" / "clean_hypervisor_coherent.jsonl")
        self.assertEqual(StartupEmulator().emulate(events), [])

    def test_fixture_only_boundary_rejects_live_capture(self) -> None:
        event = {
            "schema": OBSERVATION_SCHEMA,
            "schema_version": OBSERVATION_SCHEMA_VERSION,
            "source": "local_baseline",
            "sequence": 0,
            "event_type": "fixture_metadata",
            "captured_at": "2026-08-25T00:00:00Z",
            "raw_artifact_path": "temporary.jsonl",
            "payload": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local.jsonl"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaises(FixtureSchemaError):
                load_recorded_fixture(path)

    def test_matrix_is_explicit_about_fixture_only_scope(self) -> None:
        matrix = json.loads((LAB / "be_eac_test_matrix.json").read_text(encoding="utf-8"))
        validate_test_matrix(matrix)
        self.assertEqual(matrix["real_anti_cheat_validation"], "not-performed")
        self.assertEqual(set(matrix["deferred_bridges"]), {"real-binary", "KEVLAR"})


if __name__ == "__main__":
    unittest.main()
