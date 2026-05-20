"""Shared test fixtures.

Tests connect to a real Postgres instance — the API has no SQLite or
in-memory fallback. Set ``AETHERIX_TEST_DATABASE_URL`` to point at a
disposable database (the ``docker-compose.yml`` at the repository root
provides one on ``localhost:5432``).

Every test runs against a freshly truncated schema so they remain
order-independent.
"""

from __future__ import annotations

import os

import pytest

from app import db as app_db


_TEST_URL_DEFAULT = "postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix_test"


@pytest.fixture(scope="session", autouse=True)
def _configure_database_url() -> None:
    os.environ["AETHERIX_DATABASE_URL"] = os.environ.get(
        "AETHERIX_TEST_DATABASE_URL", _TEST_URL_DEFAULT
    )
    app_db.reset_pool()
    app_db.init_schema()


@pytest.fixture(autouse=True)
def _truncate_tables() -> None:
    """Wipe every table before each test so tests are isolated."""

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            truncate table
                heartbeats,
                alerts,
                acknowledged_alerts,
                enrollment_tokens,
                enrolled_agents,
                quick_deploy_links,
                installer_builds,
                policy_assignments,
                policy_packages,
                customer_groups,
                license_usage_daily,
                license_products,
                company_licenses,
                subscriptions,
                impersonation_sessions,
                account_roles,
                accounts,
                customer_ai_settings,
                customer_ai_usage_daily,
                customers,
                partners,
                policy_documents,
                audit_log
            restart identity cascade
            """
        )
    yield


@pytest.fixture
def promote_default_policy():
    """Promote a minimal active policy. Returns the resulting document.

    Use this in tests that previously relied on the removed env-based
    fallback (``AETHERIX_POLICY_MODE`` / ``AETHERIX_PROTECTED_ENTITIES``).
    """

    from app.schemas import PolicyDocumentDraft, PolicyRule
    from app.services.policy import promote_policy_document

    def _promote(
        *,
        mode: str = "monitor",
        entities: list[str] | None = None,
        genai_guardrail: bool = True,
        escalate_at: str = "high",
    ):
        rules = [
            PolicyRule(id=f"pii.{entity.lower()}", kind="entity", entity_type=entity, action="block")
            for entity in (entities or ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
        ]
        draft = PolicyDocumentDraft(
            name="Test policy",
            mode_default=mode,
            escalate_at=escalate_at,
            genai_guardrail=genai_guardrail,
            rules=rules,
        )
        return promote_policy_document(draft, actor="tests")

    return _promote
