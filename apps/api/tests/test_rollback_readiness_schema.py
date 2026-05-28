from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas import (
    AgentRollbackSimulation,
    RollbackIntentRequest,
    RollbackPathDecision,
    RollbackReadiness,
    RollbackRestoreRequest,
)


def _load_vss_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).resolve().parents[3] / "apps/api/tests/fixtures/vss_readiness_pending_inbox_export.json"
    return json.loads(fixture_path.read_text())


def test_rollback_readiness_accepts_empty_payload() -> None:
    readiness = RollbackReadiness.model_validate({})

    assert readiness.functional is True
    assert readiness.recovery_points == []
    assert readiness.recovery_point_count == 0


def test_rollback_readiness_normalizes_mixed_recovery_points() -> None:
    readiness = RollbackReadiness.model_validate(
        {
            "provider_name": "vss",
            "recovery_point_count": 0,
            "recent_fim_paths": ["/data/a", None, "/data/b"],
            "recovery_points": [
                {
                    "recovery_point_id": "rp-legacy-001",
                    "created": "2026-05-28T08:00:00Z",
                    "path": "/home",
                    "is_verified": True,
                },
                {
                    "id": "rp-modern-001",
                    "provider": "native",
                    "created_at": "2026-05-28T09:00:00Z",
                    "protected_root": "/var",
                    "verified": False,
                },
                "skip-me",
                {"created_at": "2026-05-28T10:00:00Z"},
            ],
        }
    )

    assert readiness.recovery_point_count == 2
    assert [point.id for point in readiness.recovery_points] == ["rp-legacy-001", "rp-modern-001"]
    assert readiness.recovery_points[0].provider == "vss"
    assert readiness.recovery_points[0].protected_root == "/home"
    assert readiness.recovery_points[0].verified is True
    assert readiness.recent_fim_paths == ["/data/a", "/data/b"]


def test_rollback_readiness_preserves_vss_provider_metadata() -> None:
    fixture = _load_vss_fixture()["rollback_readiness"]
    readiness = RollbackReadiness.model_validate(fixture)

    assert readiness.provider_name == "vss"
    assert readiness.provider_metadata is not None
    assert readiness.provider_metadata["vss_shadow_copy_id"] == "{11111111-2222-3333-4444-555555555555}"
    assert readiness.provider_metadata["vss_writer_status"]["SqlServerWriter"] == "Stable"
    assert readiness.model_dump()["vss_probe_details"]["service_state"] == "running"


def test_rollback_requests_allow_optional_provider_metadata() -> None:
    restore_without_metadata = RollbackRestoreRequest.model_validate(
        {
            "simulation_id": "sim-001",
            "candidate_set_hash": "hash-001",
            "affected_paths": ["C:\\Users\\Alice\\Documents\\report.docx"],
            "recovery_point_id": "rp-001",
            "provider": "vss",
            "severity_hint": "high",
        }
    )
    restore_with_empty_metadata = RollbackRestoreRequest.model_validate(
        {
            "simulation_id": "sim-002",
            "candidate_set_hash": "hash-002",
            "affected_paths": ["C:\\Users\\Alice\\Documents\\report.docx"],
            "recovery_point_id": "rp-002",
            "provider": "vss",
            "provider_metadata": {},
            "severity_hint": "high",
        }
    )

    intent_with_empty_metadata = RollbackIntentRequest.model_validate(
        {
            "simulation_id": "sim-003",
            "candidate_set_hash": "hash-003",
            "affected_paths": ["C:\\Users\\Alice\\Documents\\report.docx"],
            "recovery_point_id": "rp-003",
            "provider": "vss",
            "provider_metadata": {},
            "valid_until": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "severity_hint": "high",
        }
    )

    assert restore_without_metadata.provider_metadata is None
    assert restore_with_empty_metadata.provider_metadata == {}
    assert intent_with_empty_metadata.provider_metadata == {}


# ---------------------------------------------------------------------------
# RollbackPathDecision guard tests
# ---------------------------------------------------------------------------


def test_rollback_path_decision_accepts_all_outcomes() -> None:
    """Each valid RollbackPathOutcome literal must be accepted by the schema."""
    outcomes = ["restored", "skipped", "failed_integrity", "refused_out_of_scope"]
    for outcome in outcomes:
        dec = RollbackPathDecision.model_validate(
            {"path": "C:\\test\\file.txt", "outcome": outcome, "reason": "test"}
        )
        assert dec.outcome == outcome


def test_rollback_path_decision_with_metadata_diff() -> None:
    """RollbackPathDecision accepts hash_before/after and metadata_diff fields."""
    dec = RollbackPathDecision.model_validate(
        {
            "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "outcome": "refused_out_of_scope",
            "reason": "unsafe_overwrite",
            "bytes_affected": 0,
            "hash_before": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "hash_after": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            "metadata_diff": ["live_modified_after_recovery_point"],
        }
    )
    assert dec.hash_before is not None
    assert dec.hash_after is not None
    assert dec.metadata_diff == ["live_modified_after_recovery_point"]
    assert dec.bytes_affected == 0


def test_rollback_path_decision_defaults() -> None:
    """Only ``path`` and ``outcome`` are required; defaults apply to everything else."""
    dec = RollbackPathDecision.model_validate({"path": "/some/file.dat", "outcome": "skipped"})
    assert dec.reason == ""
    assert dec.bytes_affected == 0
    assert dec.hash_before is None
    assert dec.hash_after is None
    assert dec.metadata_diff is None


def test_rollback_path_decision_extra_fields_allowed() -> None:
    """extra='allow' must preserve unknown fields for forward-compatibility."""
    dec = RollbackPathDecision.model_validate(
        {
            "path": "/file.dat",
            "outcome": "failed_integrity",
            "future_agent_field": "some_value",
        }
    )
    dumped = dec.model_dump()
    assert dumped["future_agent_field"] == "some_value"


def test_rollback_path_decision_rejects_invalid_outcome() -> None:
    """An unknown outcome literal must raise a ValidationError."""
    with pytest.raises(Exception):  # pydantic.ValidationError
        RollbackPathDecision.model_validate({"path": "/f.dat", "outcome": "teleported"})


# ---------------------------------------------------------------------------
# AgentRollbackSimulation guard tests
# ---------------------------------------------------------------------------

_VALID_UNTIL = (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def test_agent_rollback_simulation_from_vss_fixture() -> None:
    """Load the full simulate_restore_output from the VSS fixture and validate."""
    fixture_path = Path(__file__).resolve().parents[3] / "apps/api/tests/fixtures/vss_readiness_pending_inbox_export.json"
    sim_data = json.loads(fixture_path.read_text())["simulate_restore_output"]
    sim = AgentRollbackSimulation.model_validate(sim_data)

    assert sim.simulation_id == "sim-vss-smoke-001"
    assert sim.candidate_count == 3
    assert sim.restorable_count == 2
    assert len(sim.skipped_paths) == 1
    assert sim.skipped_paths[0].outcome == "refused_out_of_scope"
    assert sim.provider == "vss"
    assert sim.recovery_point_id == "rp-vss-guard-001"
    assert len(sim.affected_paths) == 3


def test_agent_rollback_simulation_confidence_calculation() -> None:
    """simulation_confidence = restorable / candidate; zero-safe."""
    sim_two_thirds = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-conf-001",
            "candidate_set_hash": "h",
            "candidate_count": 3,
            "restorable_count": 2,
            "valid_until": _VALID_UNTIL,
        }
    )
    assert sim_two_thirds.simulation_confidence == pytest.approx(0.6667, abs=1e-3)

    sim_zero = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-conf-zero",
            "candidate_set_hash": "h",
            "candidate_count": 0,
            "restorable_count": 0,
            "valid_until": _VALID_UNTIL,
        }
    )
    assert sim_zero.simulation_confidence == 0.0

    sim_full = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-conf-full",
            "candidate_set_hash": "h",
            "candidate_count": 5,
            "restorable_count": 5,
            "valid_until": _VALID_UNTIL,
        }
    )
    assert sim_full.simulation_confidence == pytest.approx(1.0)


def test_agent_rollback_simulation_normalizes_skipped_paths() -> None:
    """skipped_paths list must be parsed into RollbackPathDecision objects."""
    sim = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-skip-001",
            "candidate_set_hash": "h",
            "candidate_count": 2,
            "restorable_count": 1,
            "skipped_paths": [
                {"path": "C:\\file.txt", "outcome": "skipped", "reason": "excluded by policy"},
            ],
            "valid_until": _VALID_UNTIL,
        }
    )
    assert len(sim.skipped_paths) == 1
    assert isinstance(sim.skipped_paths[0], RollbackPathDecision)
    assert sim.skipped_paths[0].reason == "excluded by policy"


def test_agent_rollback_simulation_extra_fields_allowed() -> None:
    """extra='allow' on AgentRollbackSimulation preserves unknown agent fields."""
    sim = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-extra",
            "candidate_set_hash": "h",
            "valid_until": _VALID_UNTIL,
            "agent_build": "0.2.0-pre",
            "os_build": "Windows Server 2022",
        }
    )
    dumped = sim.model_dump()
    assert dumped["agent_build"] == "0.2.0-pre"
    assert dumped["os_build"] == "Windows Server 2022"


def test_agent_rollback_simulation_decision_trace_stored() -> None:
    """decision_trace list is preserved verbatim."""
    trace = [
        "vss simulation recovery_point_id=rp-001",
        "vss simulation protected_root=C:\\",
        "vss simulation: 2 candidate(s), 2 restorable, 0 skipped/refused",
    ]
    sim = AgentRollbackSimulation.model_validate(
        {
            "simulation_id": "sim-trace",
            "candidate_set_hash": "h",
            "valid_until": _VALID_UNTIL,
            "decision_trace": trace,
        }
    )
    assert sim.decision_trace == trace

