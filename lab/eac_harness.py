"""Fixture-only EAC/EOS startup observation emulator.

This module models an explicitly bounded subset of startup observations.  It does
not load, attach to, invoke, or validate Easy Anti-Cheat, BattlEye, games, or
drivers.  The emulator accepts JSONL recordings marked ``recorded_fixture``
only, so local-baseline captures cannot accidentally be represented as
anti-cheat validation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

OBSERVATION_SCHEMA = "ophion.eac.startup-observation"
OBSERVATION_SCHEMA_VERSION = "1.0"
MATRIX_SCHEMA = "ophion.eac.be-eac-test-matrix"
MATRIX_SCHEMA_VERSION = "1.0"
RECORDED_FIXTURE_SOURCE = "recorded_fixture"

OBSERVATION_TYPES = frozenset(
    {
        "fixture_metadata",
        "system_hypervisor_detail",
        "cpuid",
        "kuser_qpc_sample",
        "synthetic_msr_access",
        "process_inventory",
        "thread_inventory",
        "module_inventory",
        "memory_inventory",
        "nmi_sample_metadata",
        "image_verification",
        "stack_walk",
        "tpm_measured_boot_result",
    }
)

# This is a deliberately small documented floor, not a Hyper-V implementation.
# Values specify direction(s) that recorded observations may claim as valid.
SYNTHETIC_MSR_FLOOR: Mapping[int, frozenset[str]] = {
    0x40000000: frozenset({"read", "write"}),  # guest OS ID
    0x40000002: frozenset({"read"}),  # VP index
    0x40000003: frozenset({"write"}),  # reset
    0x40000080: frozenset({"read"}),  # SINT0
    0x40000081: frozenset({"read"}),  # SINT1
    0x40000082: frozenset({"read"}),  # SINT2
    0x40000083: frozenset({"read"}),  # SINT3
    0x40000084: frozenset({"write"}),  # EOI
}


class FixtureSchemaError(ValueError):
    """Raised when a purported fixture is not a valid recorded observation."""


@dataclass(frozen=True)
class Finding:
    detector_id: str
    classification: str
    detector_kind: str
    evidence: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "classification": self.classification,
            "detector_kind": self.detector_kind,
            "evidence": dict(self.evidence),
        }


def _require(mapping: Mapping[str, Any], name: str, expected_type: type) -> Any:
    value = mapping.get(name)
    if not isinstance(value, expected_type):
        raise FixtureSchemaError("%s must be a %s" % (name, expected_type.__name__))
    return value


def _parse_msr(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise FixtureSchemaError("synthetic MSR must be an integer or numeric string")


def _parse_address(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise FixtureSchemaError("address must be an integer or numeric string")


def load_recorded_fixture(path: Path | str) -> List[Dict[str, Any]]:
    """Load a JSONL fixture while enforcing the fixture-only input boundary."""
    fixture_path = Path(path)
    events: List[Dict[str, Any]] = []
    previous_sequence = -1
    for line_number, line in enumerate(fixture_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FixtureSchemaError("invalid JSON on line %d: %s" % (line_number, exc)) from exc
        if not isinstance(event, dict):
            raise FixtureSchemaError("line %d must contain an object" % line_number)
        if event.get("schema") != OBSERVATION_SCHEMA:
            raise FixtureSchemaError("line %d has an unsupported observation schema" % line_number)
        if event.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
            raise FixtureSchemaError("line %d has an unsupported observation version" % line_number)
        if event.get("source") != RECORDED_FIXTURE_SOURCE:
            raise FixtureSchemaError("line %d is not a recorded fixture" % line_number)
        sequence = _require(event, "sequence", int)
        if sequence <= previous_sequence:
            raise FixtureSchemaError("line %d sequence is not strictly monotonic" % line_number)
        previous_sequence = sequence
        event_type = _require(event, "event_type", str)
        if event_type not in OBSERVATION_TYPES:
            raise FixtureSchemaError("line %d has unknown event type %r" % (line_number, event_type))
        _require(event, "captured_at", str)
        _require(event, "raw_artifact_path", str)
        _require(event, "payload", dict)
        events.append(event)
    if not events:
        raise FixtureSchemaError("fixture has no events")
    return events


def validate_test_matrix(matrix: Mapping[str, Any]) -> None:
    """Validate the intentionally compact, versioned BE/EAC fixture matrix."""
    if matrix.get("schema") != MATRIX_SCHEMA:
        raise FixtureSchemaError("unsupported matrix schema")
    if matrix.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise FixtureSchemaError("unsupported matrix version")
    if matrix.get("validation_scope") != "mock-fixtures-only":
        raise FixtureSchemaError("matrix must be explicitly mock-fixtures-only")
    if matrix.get("real_anti_cheat_validation") != "not-performed":
        raise FixtureSchemaError("matrix must explicitly disclaim real anti-cheat validation")
    strata = _require(matrix, "strata", list)
    required_strata = {
        "clean-bare-metal",
        "hyper-v-vbs",
        "runtime-ophion",
        "boot-ophion",
        "attachment",
    }
    if not required_strata.issubset(set(strata)):
        raise FixtureSchemaError("matrix is missing a required stratum")
    rows = _require(matrix, "detector_rows", list)
    if not rows:
        raise FixtureSchemaError("matrix must have detector rows")
    classifications = {"pass", "fail", "skip", "inconclusive"}
    kinds = {"hard", "heuristic"}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise FixtureSchemaError("matrix row %d must be an object" % index)
        for key in ("id", "stratum", "source", "revision", "expected_evidence", "raw_artifact_path"):
            _require(row, key, str)
        if row["stratum"] not in strata:
            raise FixtureSchemaError("matrix row %d has an unknown stratum" % index)
        if row.get("classification") not in classifications:
            raise FixtureSchemaError("matrix row %d has invalid classification" % index)
        if row.get("detector_kind") not in kinds:
            raise FixtureSchemaError("matrix row %d has invalid detector kind" % index)


class StartupEmulator:
    """Evaluate bounded invariants against recorded startup observations."""

    def emulate(self, events: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Finding] = []
        hypervisor_detail: Mapping[str, Any] | None = None
        cpuid: Mapping[str, Any] | None = None
        qpc_previous: Mapping[str, Any] | None = None
        images: List[Mapping[str, Any]] = []
        modules: Dict[str, Mapping[str, Any]] = {}

        for event in events:
            event_type = event["event_type"]
            payload = event["payload"]
            sequence = event["sequence"]

            if event_type == "system_hypervisor_detail":
                hypervisor_detail = payload
                if cpuid is not None:
                    findings.extend(self._coherence_findings(hypervisor_detail, cpuid))
            elif event_type == "cpuid":
                cpuid = payload
                if hypervisor_detail is not None:
                    findings.extend(self._coherence_findings(hypervisor_detail, cpuid))
            elif event_type == "synthetic_msr_access":
                findings.extend(self._synthetic_msr_findings(payload, sequence))
            elif event_type == "kuser_qpc_sample":
                if qpc_previous is not None:
                    findings.extend(self._clock_findings(qpc_previous, payload, sequence))
                qpc_previous = payload
            elif event_type == "module_inventory":
                modules[str(payload.get("module_id", ""))] = payload
                images.append(payload)
            elif event_type == "stack_walk":
                findings.extend(self._stack_findings(payload, images, sequence))
            elif event_type == "memory_inventory":
                findings.extend(self._memory_findings(payload, sequence))
            elif event_type == "image_verification":
                findings.extend(self._image_verification_findings(payload, modules, sequence))
            elif event_type == "tpm_measured_boot_result":
                findings.extend(self._tpm_findings(payload, sequence))

        return [finding.as_dict() for finding in findings]

    @staticmethod
    def _coherence_findings(detail: Mapping[str, Any], cpuid: Mapping[str, Any]) -> Iterable[Finding]:
        detail_value = detail.get("hypervisor_present")
        cpuid_value = cpuid.get("hypervisor_present")
        if isinstance(detail_value, bool) and isinstance(cpuid_value, bool) and detail_value != cpuid_value:
            yield Finding(
                "hypervisor-cpuid-coherence",
                "fail",
                "hard",
                {
                    "system_information_class": detail.get("system_information_class"),
                    "system_hypervisor_present": detail_value,
                    "cpuid_hypervisor_present": cpuid_value,
                },
            )

    @staticmethod
    def _synthetic_msr_findings(payload: Mapping[str, Any], sequence: int) -> Iterable[Finding]:
        direction = payload.get("direction")
        msr = _parse_msr(payload.get("msr"))
        allowed = SYNTHETIC_MSR_FLOOR.get(msr, frozenset())
        if direction not in allowed:
            yield Finding(
                "synthetic-msr-direction",
                "fail",
                "hard",
                {"sequence": sequence, "msr": hex(msr), "direction": direction, "allowed": sorted(allowed)},
            )

    @staticmethod
    def _clock_findings(previous: Mapping[str, Any], current: Mapping[str, Any], sequence: int) -> Iterable[Finding]:
        for field in ("kuser_tick_100ns", "qpc_ticks"):
            before = previous.get(field)
            after = current.get(field)
            if isinstance(before, int) and isinstance(after, int) and after < before:
                yield Finding(
                    "kuser-qpc-monotonicity",
                    "fail",
                    "hard",
                    {"sequence": sequence, "field": field, "previous": before, "current": after},
                )

    @staticmethod
    def _stack_findings(payload: Mapping[str, Any], images: Sequence[Mapping[str, Any]], sequence: int) -> Iterable[Finding]:
        address = _parse_address(payload.get("return_address"))
        for image in images:
            try:
                base = _parse_address(image["base_address"])
                size = _parse_address(image["image_size"])
            except (KeyError, ValueError, FixtureSchemaError):
                continue
            if base <= address < base + size:
                return
        yield Finding(
            "stack-return-known-image",
            "fail",
            "heuristic",
            {"sequence": sequence, "return_address": hex(address), "known_image_count": len(images)},
        )

    @staticmethod
    def _memory_findings(payload: Mapping[str, Any], sequence: int) -> Iterable[Finding]:
        protection = str(payload.get("protection", "")).lower()
        executable = "x" in protection or "execute" in protection
        backed = bool(payload.get("image_backed"))
        if executable and not backed:
            yield Finding(
                "unbacked-executable-allocation",
                "fail",
                "heuristic",
                {"sequence": sequence, "allocation_id": payload.get("allocation_id"), "protection": protection},
            )

    @staticmethod
    def _image_verification_findings(payload: Mapping[str, Any], modules: Mapping[str, Mapping[str, Any]], sequence: int) -> Iterable[Finding]:
        module_id = str(payload.get("module_id", ""))
        module = modules.get(module_id)
        expected = payload.get("expected_sha256")
        observed = payload.get("observed_sha256")
        mismatch = payload.get("verification_result") == "mismatch" or (
            isinstance(expected, str) and isinstance(observed, str) and expected != observed
        )
        if module is not None and isinstance(expected, str) and module.get("sha256") != expected:
            mismatch = True
        if mismatch:
            yield Finding(
                "module-image-verification",
                "fail",
                "hard",
                {"sequence": sequence, "module_id": module_id, "expected_sha256": expected, "observed_sha256": observed},
            )

    @staticmethod
    def _tpm_findings(payload: Mapping[str, Any], sequence: int) -> Iterable[Finding]:
        state = payload.get("state")
        if state in {"unknown", "not-collected", "not-available"}:
            yield Finding(
                "tpm-measured-boot-state",
                "inconclusive",
                "heuristic",
                {"sequence": sequence, "state": state, "reason": payload.get("reason")},
            )
