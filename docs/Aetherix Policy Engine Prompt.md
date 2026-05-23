> Historical implementation prompt, not current product documentation. Use [policy-engine.md](policy-engine.md), [development.md](development.md), and the API/tests as the source of truth for implemented Policy Engine v2 behavior.

You are a senior full-stack engineer building **Aetherix** — a modern, AI-native, MSP-first next-gen endpoint security platform.

We are now implementing the **Policy Engine v2 + Default Policy v1.01** as the central control plane of the platform. This directly builds on the `Default Policy v1.01.md` document and the Companies + Licensing + Accounts module.

### Goal
Create a robust **PolicyDocumentV2** system that:
- Supports the full module structure from Default Policy v1.01
- Enables MSP Partners to assign policies to their Companies
- Enforces simulation gates before destructive actions (`block`, `isolate`, `rollback`)
- Emits evidence for the Compliance Evidence Engine
- Is fully subscription-aware (Core vs Add-on modules)
- Integrates with the existing 3-tier hierarchy (Platform Owner → MSP Partner → Company)

### Technical Requirements

**1. Backend (FastAPI + PostgreSQL)**
- New models:
  - `PolicyDocumentV2` (JSONB field with full schema from the spec)
  - `PolicyVersion` (immutable signed versions)
  - `PolicyAssignment` (links policy to customer/group/endpoint with effective resolution)
  - `PolicySimulation` (stores simulation results, approval status, evidence)
- API Endpoints:
  - `POST /policies` — create new policy (with validation against schema + entitlements)
  - `GET /policies` — list with tenant scoping + filters
  - `GET /policies/{id}` — retrieve with effective resolution preview
  - `POST /policies/{id}/simulate` — run simulation (returns what would happen per module)
  - `POST /policies/{id}/promote` — promote after simulation + approval (requires operator approval for block/isolate/rollback)
  - `POST /policies/assign` — assign to customer/group/endpoint
  - `GET /policies/effective` — resolve effective policy for a specific endpoint (with inheritance)

**2. Policy Schema (PolicyDocumentV2)**
Use the exact structure from Default Policy v1.01:
```jsonc
{
  "schema_version": "2.0",
  "name": "...",
  "scope": { "partner_id": "...", "customer_id": "...", "group_id": "...", "endpoint_id": "..." },
  "lineage": { "parent_policy_id": "...", "inheritance_mode": "inherit_with_overrides" },
  "modules": {
    "general": { ... },
    "antimalware": { ... },
    "semantic_dlp": { ... },
    "genai_guardrails": { ... },
    "digital_risk_protection": { ... },
    "external_attack_surface_management": { ... },
    // ... all modules from the spec
  }
}
```

**3. Frontend (React + Vite)**
- **Policy Editor Page** (`/policies/editor`)
  - Module-by-module accordion (General, Antimalware, Semantic DLP, GenAI Guardrails, DRP, EASM, etc.)
  - Dynamic form fields based on module schema
  - Real-time validation + subscription entitlement checks (locked modules show "Requires X add-on")
  - Simulation button (runs backend simulation and shows impact preview)
  - Approval workflow for high-impact changes

- **Policy Assignment Modal**
  - Searchable company/group/endpoint picker (respecting current user's scope)
  - Inheritance preview (shows effective policy after assignment)
  - Quick Deploy integration (one-click assign + generate installer)

- **Policy List Page** (`/policies`)
  - Table with version, scope, last modified, status (Draft / Active / Archived)
  - Filters by module, customer, simulation status
  - "Simulate" and "Assign" actions

**4. Integration Points**
- Tie to existing **Companies + Licensing** module: Policy assignment should validate against customer entitlements.
- Evidence emission: Every policy change, simulation, promotion, and assignment must emit events with `evidence_controls`.
- Agent fetch: Enrolled agents should be able to `GET /policies/effective?endpoint_id=xxx` and receive only the modules they are entitled to.
- Simulation gates: Any promotion to `block`/`isolate`/`rollback` must have a successful simulation record + operator approval.

**5. Aetherix-Specific Features**
- Subscription-gated module visibility (hide or lock unlicensed modules)
- Tenant-scoped inheritance (MSP default → Customer → Group → Endpoint)
- Signed policy versions + hash verification
- AI-assisted policy suggestions (optional, advisory only)
- White-label policy naming (MSP can rename sections for their customers)

### Deliverables (Step-by-step)

**Phase 1 (Backend Foundation)**
1. Database migrations for `PolicyDocumentV2`, `PolicyVersion`, `PolicyAssignment`, `PolicySimulation`
2. Pydantic models + FastAPI router for the core endpoints above
3. Policy validation service (against JSON schema + entitlement checks)
4. Effective policy resolution logic (inheritance + overrides)
5. Simulation engine stub (returns mock impact per module for now)

**Phase 2 (Frontend)**
6. Policy list page + filters
7. Policy editor with dynamic forms + simulation button
8. Assignment modal with scope picker and inheritance preview
9. Integration with existing Companies page (add "Assign Policy" action)

**Phase 3 (Polish & Evidence)**
10. Full evidence emission on all policy actions
11. Signed policy versioning + hash verification
12. Agent-side policy fetch endpoint + basic enforcement stub

### Acceptance Criteria
- A PolicyDocumentV2 can be created, versioned, simulated, approved, and assigned to a Company.
- Unlicensed modules are hidden or clearly marked as locked based on customer subscription.
- Simulation is required before any `block`/`isolate`/`rollback` promotion.
- Every policy action emits audit + evidence records.
- MSP Partner can only see/assign policies within their tenant scope.
- Agent can fetch effective policy for an enrolled endpoint.

Start by showing me:
- Updated Prisma/SQLAlchemy models
- Core API route structure (FastAPI)
- High-level component breakdown for the Policy Editor page

Use the exact module structure and defaults from **Default Policy v1.01.md**. Make this the durable foundation for the Aetherix control plane.