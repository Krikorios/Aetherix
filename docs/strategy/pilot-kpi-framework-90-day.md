# Aetherix 90-Day Pilot KPI Framework

Status: draft, May 2026. Audience: design-partner MSPs, product, and operations.

This framework defines how to evaluate pilot success across security outcomes,
operational efficiency, compliance output, and commercial viability.

## 1) Pilot Goals

Primary objective:

- Prove that Aetherix improves security control, reduces delivery overhead, and
  accelerates compliance evidence workflows in MSP-managed environments.

Secondary objective:

- Establish repeatable onboarding and tuning playbooks for broader channel scale.

## 2) Pilot Scope and Preconditions

Recommended pilot shape:

- 1 MSP partner, 2 to 4 customer environments, 100 to 1000 endpoints total
- Mixed user populations with measurable GenAI usage
- At least one compliance-driven customer profile

Preconditions before Day 1:

- Endpoint deployment plan confirmed
- Policy package baseline agreed (`monitor` default for new controls)
- Data handling and legal terms signed
- Success metrics and reporting cadence approved by both sides

## 3) Phased Timeline

### Phase 0 (Days 0 to 14): Baseline and Deployment

Track:

- Endpoint onboarding rate
- Active agent heartbeat coverage
- Browser extension active coverage (where applicable)
- Baseline incident and evidence-prep cycle times

Deliverables:

- Baseline KPI snapshot
- Pilot operating runbook

### Phase 1 (Days 15 to 45): Detection and Control Validation

Track:

- GenAI paste/upload/copy events inspected
- Policy action distribution (`monitor`, `review`, `block`)
- True positive precision for high-risk policy actions
- Alert-to-investigation SLA attainment

Deliverables:

- Weekly efficacy report
- Tuning log with approved policy changes

### Phase 2 (Days 46 to 90): Operational and Compliance Validation

Track:

- Evidence packet generation time by framework
- Audit-prep labor hours saved
- Investigation time reduction vs baseline
- Candidate attach/upsell opportunities by customer segment

Deliverables:

- Final scorecard
- Executive pilot outcome summary
- Go/No-Go recommendation

## 4) KPI Categories and Definitions

Security efficacy:

- Policy action precision (high-risk events)
- Control coverage rate (agent + extension where deployed)
- High-severity event handling SLA

Operational efficiency:

- Mean time to triage
- Mean time to investigation closure
- Analyst/engineer hours per incident or review queue

Compliance output:

- Time to generate framework-scoped evidence pack
- Completeness ratio of required artefacts
- Number of manual evidence collection steps removed

Commercial signal:

- Service attach opportunities identified
- Expansion intent from pilot stakeholders
- Estimated gross-margin impact from workflow consolidation

## 5) Scorecard Thresholds (Example)

Use this traffic-light model unless partner-specific targets are negotiated.

Security efficacy:

- Green: policy precision >= 90% and control coverage >= 95%
- Yellow: policy precision 75 to 89% or control coverage 85 to 94%
- Red: policy precision < 75% or control coverage < 85%

Operational efficiency:

- Green: >= 30% reduction in investigation or evidence-prep time
- Yellow: 15 to 29% reduction
- Red: < 15% reduction

Compliance output:

- Green: >= 40% reduction in evidence preparation cycle time
- Yellow: 20 to 39% reduction
- Red: < 20% reduction

Commercial signal:

- Green: >= 2 credible expansion opportunities per pilot segment
- Yellow: 1 credible expansion opportunity
- Red: no credible expansion signal

## 6) Weekly Reporting Template

Minimum weekly pack:

1. KPI trend table (current week vs baseline)
2. Significant incidents and policy outcomes
3. False-positive and exception analysis
4. Deployment/tuning changes made and rationale
5. Risks, blockers, and mitigation plan

## 7) Governance and Change Control

Pilot governance rules:

- Start with `monitor` for new or unproven detections
- Move to `review` or `block` only with explicit operator approval
- Log all material policy changes with timestamp and approver
- Preserve tenant isolation and least-privilege access throughout pilot

## 8) Exit Criteria (Go/No-Go)

Go:

- Security and operational categories are Green or Yellow
- No unresolved Red in core control efficacy
- Partner confirms repeatable deployment model for next customers

Conditional Go:

- One category remains Yellow with a time-bound remediation plan

No-Go/Pivot:

- Persistent Red in efficacy or unacceptable deployment friction
- False-positive burden remains operationally unacceptable

## 9) Post-Pilot Outputs

Required outputs after pilot close:

- Redacted case study with quantified outcomes
- Final implementation checklist and onboarding playbook updates
- Product gap list prioritized by commercial impact
- Joint statement of next rollout scope and timing
