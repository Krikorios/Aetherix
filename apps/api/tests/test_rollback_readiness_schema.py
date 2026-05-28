from __future__ import annotations

import json
from pathlib import Path

from app.schemas import RollbackReadiness


def _load_vss_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).resolve().parents[3] / "apps/console/src/test/fixtures/vss-smoke.json"
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
