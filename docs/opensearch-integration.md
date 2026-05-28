# OpenSearch Integration — Getting Started (P1-1.5)

**Status**: First slice implemented (docker-compose service + client wrapper + dual-write for security alerts + smoke endpoint).

This is the foundational workstream for scalable log/event retention, "Live Search", and the Native SIEM/HIDS module.

See:
- [architecture.md §3.3.1](../architecture.md) — full design (ingestion patterns, ILM, tenant isolation, compliance boundary)
- [roadmap-2026.md](../roadmap-2026.md) — P1-1.5 with concrete tasks and exit criteria

## 1. One-time local setup

```bash
# From repo root
docker compose up -d postgres opensearch

# Wait for OpenSearch to become healthy (first run pulls ~600MB image)
docker compose ps opensearch
curl -s http://localhost:9200/_cluster/health | jq
```

## 2. Install the client in the API venv

```bash
cd apps/api
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Run the API with OpenSearch enabled

```bash
AETHERIX_OPENSEARCH_URL=http://localhost:9200 \
PYTHONPATH=apps/api \
apps/api/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On startup you should see a log line similar to:
```
INFO ... OpenSearch client initialized successfully at http://localhost:9200
INFO ... OpenSearch integration warmed up
```

## 4. Exercise the smoke test (Platform Owner only)

Use the existing dev auth path (or a real Platform Owner account once auth is hardened).

```bash
# Get a customer_id from your local data (or create one)
curl -s 'http://127.0.0.1:8000/companies/summary?limit=1' \
  -H 'X-Aetherix-Account: <your-platform-owner-id>' | jq

# Trigger the smoke (replace CUSTOMER_ID)
curl -X POST 'http://127.0.0.1:8000/internal/opensearch/smoke?customer_id=CUSTOMER_ID' \
  -H 'X-Aetherix-Account: <your-platform-owner-id>' | jq
```

Expected successful response shape:
```json
{
  "enabled": true,
  "indexed": true,
  "search": { "hits": 1 },
  "index_pattern_hint": "aetherix-events-*-<customer-uuid-with-underscores>"
}
```

You can also inspect directly:
```bash
curl -s 'http://localhost:9200/aetherix-events-*-<customer-uuid-with-underscores>/_search?pretty' | jq
```

## 5. What is wired today (expanded first slice)

- `docker-compose.yml`: `opensearch` service (security disabled for local dev).
- `apps/api/requirements.txt`: `opensearch-py==2.7.1`.
- `apps/api/app/services/event_index.py`:
  - Full **Data Streams** support (not regular indices)
  - Modern composable-style index template with `data_stream: {}`
  - ILM policy management (`ensure_ilm_policies` creates 30d/90d/365d/7y policies)
  - Automatic rollover configuration
  - `@timestamp` as primary time field (Data Stream requirement)
  - Convenience helpers for security_alert / fim / dlp events
  - `search_events()` read helper
- Dual-write coverage: security_alerts + fim_events + dlp_events
- Real search: `GET /customers/{customer_id}/events/search`
- Smoke test + warmup now ensure both ILM policies and data stream templates
- All documents contain `@timestamp` + `postgres_ref` + tenant fields.

## 6. Next immediate work (from roadmap P1-1.5)

1. ~~Add dual-write for `fim_events` and `dlp_events`~~ (done in this slice).
2. Add a real "Live Search" / Events workspace in the console (the backend endpoint `GET /customers/{id}/events/search` is now ready).
3. Implement ILM policy management driven by customer retention settings + legal hold.
4. Add OpenSearch as a first-class connector target in `integrations.py`.
5. Improve document shaping, add more raw SIEM log support when collectors land.
6. Production hardening (auth, TLS, data streams, proper ILM hot/warm/cold policies).

## 7. Data Streams + Index Lifecycle Management (current implementation)

We use **OpenSearch Data Streams** (not regular indices) for all security events.

Benefits:
- Automatic rollover of backing indices (daily or by size/doc count)
- Clean separation of hot data vs older data
- Native integration with ILM for retention

### Standard ILM Policies (created on warmup)

| Policy                    | Retention | Typical use case                  |
|---------------------------|-----------|-----------------------------------|
| `aetherix-security-30d`   | 30 days   | Low-tier / high-volume customers  |
| `aetherix-security-90d`   | 90 days   | **Default** for most customers    |
| `aetherix-security-365d`  | 1 year    | Regulated customers               |
| `aetherix-security-7y`    | ~7 years  | Long-term compliance requirements |

Each customer data stream (`aetherix-events-{partner}-{customer}`) currently uses the 90-day policy by default.

**Implemented**: ILM policy is now selected dynamically per customer based on the `event_retention_days` column on the `customers` table (see `resolve_ilm_policy_for_customer` + `get_customer_event_retention_days` in `event_index.py`).

- If `event_retention_days` is NULL → uses 90-day default.
- The system maps the value to the closest standard policy (30d / 90d / 365d / 7y).
- The correct policy is applied to the customer's data stream write index on first (and subsequent) writes.

Data streams are created automatically on first document write for a customer.

## How to test dynamic retention right now

You can set different retention per customer directly in the database:

```sql
-- Example: give this customer 365-day retention
UPDATE customers 
SET event_retention_days = 365 
WHERE id = 'your-customer-uuid';
```

After the update, generate one new event for that customer (e.g. a DLP scan or agent heartbeat that produces an alert). The next document written will cause the customer's data stream write index to be updated to `aetherix-security-365d`.

You can verify with:

```bash
curl -s 'http://localhost:9200/_data_stream/aetherix-events-*-<customer-uuid-with-underscores>?pretty' | jq
```

Look for the `ilm_policy` on the write index.

## 9. Important invariants (do not violate)

- OpenSearch is **never** the source of truth for compliance exports or the hash chain.
- Every document must contain `partner_id` + `customer_id` + `postgres_ref` + `@timestamp`.
- The primary request path must never fail or be slowed down by OpenSearch.
- Tenant isolation is enforced in the Python layer (data stream naming + query filters).

## Troubleshooting

- `enabled: false` on smoke → `AETHERIX_OPENSEARCH_URL` is not set in the process that runs the API.
- Indexing returns false but no crash → look at API logs for `OpenSearch index failed`.
- Template not appearing → call `ensure_templates()` manually or restart the API after OpenSearch is healthy.
- Permission / security errors in prod → re-enable the security plugin in OpenSearch and switch to API-key or mTLS auth (documented in a future revision of this file).

This slice is intentionally small and safe so the broader team can start experimenting with search, retention policies, and the future SIEM collectors immediately.
