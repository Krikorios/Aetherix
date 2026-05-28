import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.db import connection
from app.main import app


def test_action_queue_resolves_endpoint_customer_when_action_customer_is_null(
    tenant_hierarchy_factory, auth_headers
) -> None:
    tenant = tenant_hierarchy_factory(endpoint_id="agent-queue-scope-001")
    action_id = uuid.uuid4()

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into module_actions(
                id, endpoint_id, action, payload, status, approval_required,
                created_by, created_at, evidence_controls, customer_id
            ) values (%s, %s, 'push_policy_update', null, 'queued', false, 'tests', %s, '[]'::jsonb, null)
            """,
            (action_id, tenant["endpoint_id"], datetime.now(UTC)),
        )

    client = TestClient(app)
    response = client.get("/actions/queue", headers=auth_headers(tenant["company_admin_id"]))

    assert response.status_code == 200, response.text
    rows = response.json()
    assert [row["id"] for row in rows] == [str(action_id)]
    assert rows[0]["hostname"] == "e2e-host"
    assert rows[0]["customer_name"] == "E2E Customer"


def test_action_queue_cancel_allows_scoped_user_when_action_customer_is_null(
    tenant_hierarchy_factory, auth_headers
) -> None:
    tenant = tenant_hierarchy_factory(endpoint_id="agent-queue-cancel-001")
    action_id = uuid.uuid4()

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into module_actions(
                id, endpoint_id, action, payload, status, approval_required,
                created_by, created_at, evidence_controls, customer_id
            ) values (%s, %s, 'push_policy_update', null, 'queued', false, 'tests', %s, '[]'::jsonb, null)
            """,
            (action_id, tenant["endpoint_id"], datetime.now(UTC)),
        )

    client = TestClient(app)
    response = client.post(
        f"/actions/{action_id}/cancel",
        headers=auth_headers(tenant["company_admin_id"]),
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"
