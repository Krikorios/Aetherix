# Aetherix Investor Memo (Draft)

Status: draft, May 2026. Audience: investors, board, and strategic advisors.

This memo is designed to be used as a fast diligence brief. It is grounded in
the current repository state and the documented roadmap. It is not a production
readiness claim.

## 1) Investment Thesis

Aetherix is building an MSP-first security platform that unifies three budgets
that SMB customers currently buy separately:

1. Endpoint protection and response
2. Data loss prevention, including GenAI browser channels
3. Compliance evidence generation for audits

The product thesis is simple: one signed agent, one tenant-scoped policy model,
and one evidence chain can replace fragmented tool stacks and improve MSP margin.

## 2) Problem Statement

MSPs serving SMBs are under pressure from:

- Tool sprawl: separate products for endpoint, DLP, browser controls, and GRC
- Margin compression: service delivery overhead increases with each console/agent
- Compliance burden: audit evidence remains manual and labor intensive
- GenAI risk growth: sensitive data movement now happens inside browser sessions

Incumbent categories solve parts of this problem, but usually not all in one
native platform.

## 3) Why Now

- GenAI adoption has shifted data exfiltration risk into browser session flows.
- SMB compliance requirements continue to expand (SOC 2, ISO 27001, HIPAA, etc.).
- MSPs need higher-margin, repeatable managed security and compliance offerings.

This timing creates a wedge for a platform that can prove protection outcomes and
produce audit-ready evidence from the same telemetry stream.

## 4) Product and Current Proof

Current POC strengths (implemented in repo):

- Policy Engine v2 with simulation-before-enforcement workflows
- Semantic DLP + GenAI guardrail policy modules
- Rust endpoint agent with enrollment, signed heartbeat, policy fetch/cache, and offline queue
- MV3 browser extension foundation with GenAI destination interception logic
- Compliance Evidence Engine v0 with signed export bundle support
- MSP console foundation for customers, licensing, accounts, and deployment flow

Open gaps before broad commercial rollout:

- Production authentication/session hardening
- Signed installer trust chain across Windows, macOS, Linux
- Native AV/EDR deterministic depth (YARA/IOC/process behavior/ransomware canaries)
- Real-site extension hardening against DOM drift on major GenAI targets

## 5) Strategic Differentiation

Aetherix aims to differentiate on architecture, not just packaging:

- Native cross-surface policy model across endpoint, DLP, and evidence
- Browser-session-level GenAI controls integrated with endpoint and tenant policy
- Evidence-by-construction model (event to control mapping at write time)
- MSP-native multi-tenancy and licensing model from day one

## 6) Business Model and Packaging

Planned SKU structure:

- `Core`: endpoint foundations + incident and telemetry operations
- `+GenAI` (Core add-on): browser guardrails + semantic DLP for GenAI destinations
- `+CompliancePro` (Core add-on): framework-mapped evidence workflows and auditor exports

Commercial logic:

- Land on Core with managed protection services
- Expand with GenAI governance for knowledge-worker clients
- Upsell CompliancePro for audit-driven industries and recurring vCISO programs

## 7) Go-to-Market Motion

Primary channel: MSP partnerships with design-partner cohorts.

Initial target segment:

- Regulated SMBs and mid-market teams
- High GenAI usage profiles
- Customers with annual compliance attestations

Execution model:

- Start with 3 to 5 design-partner MSPs
- Use 90-day pilots with strict success scorecards
- Convert pilot proof into repeatable onboarding and sales collateral

## 8) 12-Month Milestones

Quarterly sequence:

- Q1: production auth/RBAC, signed installer pipeline, pilot packaging
- Q2: deterministic AV/EDR v0 and extension resilience suite
- Q3: design-partner expansion and publishable pilot outcomes
- Q4: repeatable channel onboarding with clear attach/expansion motion

Target KPI categories:

- Security efficacy: precision/coverage across policy actions and detections
- Operational efficiency: time reduction in triage and evidence preparation
- Compliance output: time-to-export and audit packet completeness
- Commercial signal: attach rates, expansion rates, gross margin contribution

## 9) Key Risks and Mitigation

- AV credibility gap
  - Mitigation: deterministic detection first, transparent efficacy reporting, staged claims
- Competitive convergence from MSP-first incumbents
  - Mitigation: ship faster on GenAI browser plus evidence integration depth
- Deployment trust friction
  - Mitigation: signed artifacts, hardening baseline, operator-safe defaults
- Over-claim risk in marketing
  - Mitigation: strict capability messaging tied to implemented, tested modules

## 10) Diligence Data Pack (Recommended)

To move from draft narrative to investor-ready memo, attach:

- Feature truth table (implemented vs roadmap by module)
- Pilot design + KPI framework (see `docs/strategy/pilot-kpi-framework-90-day.md`)
- Competitive matrix with source-backed capability claims
- 12-month product and GTM operating plan with burn and hiring assumptions
