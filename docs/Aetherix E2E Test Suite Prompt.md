> Historical test-suite prompt, not current product documentation. Use [regression-hardening-report-2026-05-23.md](regression-hardening-report-2026-05-23.md), [development.md](development.md), and the test files under `apps/api/tests`, `apps/console/e2e`, and `apps/extension/test` as the current validation record.

You are a senior QA + test automation engineer building a **full end-to-end test suite** for Aetherix Policy Engine v2 + Semantic DLP + GenAI Guardrails.

The core functionality is now implemented and passing unit/integration tests. We now need a comprehensive test suite that covers the entire flow from policy creation to agent enforcement.

### Scope

Test the following new modules and flows:

1. **Policy Engine v2**
   - PolicyDocumentV2 creation, versioning, signing
   - Simulation (real impact per module)
   - Promotion gates (simulation required + approval for destructive actions)
   - Effective policy resolution with inheritance
   - Assignment to Company / Group / Endpoint with entitlement checks

2. **Semantic DLP + GenAI Guardrails**
   - Canonical module structure validation
   - Simulation impact for semantic/genai actions (paste_sensitive, upload_restricted, copy_to_genai)
   - Detector configuration (Presidio, LLM semantic, custom classifiers)
   - Browser + endpoint enforcement simulation
   - Evidence emission for DLP events

3. **Cross-Module Integration**
   - Companies + Licensing + Policy assignment flow
   - Entitlement gating (unlicensed modules blocked)
   - Compliance Evidence Engine events from policy actions

### Test Layers Required

**1. Backend (Python / pytest)**
- Expand `test_policy_v2.py` with full coverage
- New dedicated file: `test_policy_v2_e2e.py`
- New dedicated file: `test_semantic_dlp_genai.py`
- Integration tests in `test_compliance_export.py`

**2. Frontend (React + Vitest / Playwright)**
- Component tests for Policy Editor (accordion, dynamic fields, simulation button)
- Integration tests for Assignment Modal (company/group/endpoint picker, inheritance preview)
- E2E flow tests (create → simulate → promote → assign → verify effective policy)

**3. End-to-End Flows (Critical)**
Create automated tests for these complete user journeys:

**Flow A: MSP Partner creates and assigns a policy**
1. Login as MSP Partner
2. Create new PolicyDocumentV2 with Semantic DLP + GenAI Guardrails enabled
3. Run simulation → verify risk_delta and destructive action detection
4. Promote with approval
5. Assign to a Company
6. Verify Company Admin sees the policy in effective list

**Flow B: Company Admin views and overrides policy**
1. Login as Company Admin
2. View inherited policy
3. Create group-level override (e.g., stricter GenAI rules)
4. Verify effective policy for endpoint reflects override

**Flow C: Agent fetches and applies policy**
1. Enroll new endpoint for a Company
2. Call `GET /agent/policy?endpoint_id=xxx`
3. Verify only entitled modules are returned
4. Verify semantic_dlp + genai_guardrails sections are present and correctly structured

**Flow D: Destructive action gate**
1. Create policy with `block` action on restricted upload
2. Attempt promotion without simulation → should be rejected
3. Run simulation → verify approval_required = true
4. Approve promotion → verify evidence event is created

### Test Coverage Requirements

- **Happy path** for every major action (create, simulate, promote, assign, fetch)
- **Error cases**: unlicensed module assignment, missing simulation, invalid JSON schema, expired token
- **Edge cases**: deep inheritance (MSP → Customer → Group → Endpoint), empty modules, mixed Core + Add-on policies
- **Evidence emission**: every policy action must create an `EvidenceEvent` with correct `evidence_controls`
- **Performance**: simulation of full policy envelope should complete in < 500ms

### Deliverables

1. **Backend Test Suite**
   - `test_policy_v2_e2e.py` (full flows)
   - `test_semantic_dlp_genai.py` (module-specific tests)
   - Updated `test_policy_v2.py` and `test_compliance_export.py`

2. **Frontend Test Suite**
   - Vitest component tests for Policy Editor and Assignment Modal
   - Playwright E2E tests for the 4 critical flows above

3. **Test Data & Fixtures**
   - Reusable policy templates (Minimal, Strict, GenAI-Focused, DRP-Enabled)
   - Test companies, groups, and endpoints with proper hierarchy
   - Mock agent responses

4. **CI Integration**
   - Add new test jobs to GitHub Actions (or existing pipeline)
   - Ensure all new tests run on every PR

### Acceptance Criteria

- All new tests pass consistently (target: 100% pass rate)
- Every major user flow from Default Policy v1.01 has automated coverage
- Simulation + promotion gates are tested end-to-end
- Semantic DLP + GenAI Guardrails have dedicated test coverage
- Evidence events are verified in compliance export tests
- Agent fetch endpoint is tested with real policy resolution
- Test suite runs in under 5 minutes in CI

Start by showing me:
- High-level test file structure
- Example test for Flow A (MSP creates and assigns policy)
- Example test for semantic/genai simulation impact

Use the existing test patterns in the repo and the module structures from **Default Policy v1.01.md**. Make this the most comprehensive test suite in the project.