# Aetherix Next-Gen Endpoint Security Platform

Complete development proposal from zero to production-ready enterprise solution.

Prepared for the development team on May 16, 2026. Version 1.0. Confidential.

## Executive Summary

Aetherix is an AI-native endpoint security platform designed for the generative AI era. It combines a lightweight endpoint agent, semantic DLP, AI-generated vulnerability reporting, and agentic incident response into a privacy-first platform that can be deployed in cloud, self-hosted, or air-gapped environments.

The first production path should be deliberately narrow: prove the endpoint agent contract, Presidio-compatible DLP scans, policy distribution, alert workflow, and basic console in an 8-week MVP before expanding into semantic classifiers, vulnerability reporting, partner workflows, and autonomous response.

### Core Differentiators

- Semantic and contextual DLP that understands intent, data sensitivity, and destination context instead of relying only on regex and keyword rules.
- Native protection for browser-based generative AI usage, including content pasted into ChatGPT, Claude, Gemini, Copilot, and similar tools.
- AI-generated vulnerability reports with business risk scoring, prioritized remediation playbooks, and predictive what-if analysis.
- Agentic incident response that reconstructs timelines, summarizes incidents in plain English, and delivers Slack or Teams actions with human approval gates.
- Privacy-first deployment options with minimal telemetry, strong auditability, open-core options, and full on-prem support.
- Ultra-lightweight Rust agent foundation targeting less than 1% average CPU overhead and less than 50 MB resident memory on reference hardware.

## 1. Market Opportunity and Competitive Gaps

Incumbent endpoint security platforms still rely heavily on 2010s-era content rules, signature detection, and generic vulnerability dashboards. They are strong at traditional endpoint protection, but weaker at generative AI data exfiltration, business-context reporting, and autonomous incident investigation.

| Gap area | Incumbent limitation | Aetherix advantage |
| --- | --- | --- |
| DLP for GenAI | Regex and basic rules are often blind to browser AI paste events. | Semantic DLP with real-time browser guardrails and destination-aware policy. |
| Vulnerability reporting | Raw CVE lists and generic risk scores require manual analyst interpretation. | Executive-ready reports, business context, playbooks, and what-if scenarios. |
| Incident response | Automated actions exist, but noisy alerts still require high SOC effort. | Agentic investigation, timeline reconstruction, and contextual approval actions. |
| Trust and sovereignty | Some vendors face geopolitical or deployment trust constraints. | Neutral, privacy-first, open-core option with self-hosted and air-gapped paths. |
| Legacy hardware | Resource usage is acceptable but noticeable on older endpoints. | Rust-first agent architecture with strict performance budgets. |

## 2. Product Vision

Aetherix will be built around four strategic pillars.

1. Semantic DLP engine: Real-time understanding of data sensitivity and intent across files, clipboard, browser, email, cloud apps, and network destinations.
2. Continuous Threat Exposure Management: Continuous asset discovery, CVE enrichment, prioritization, and business-risk reporting.
3. Autonomous Security Operations: AI agents that investigate alerts, correlate telemetry, generate playbooks, and recommend or execute approved actions.
4. Trust and Performance Foundation: Lightweight, auditable, deploy-anywhere architecture with privacy-preserving defaults.

## 3. Detailed Feature Specification

### 3.1 Core Detection and DLP

- Presidio-compatible scanner for built-in PII entities and customer-defined regex, keyword, and exact-data-match rules.
- LLM-powered semantic classifier that distinguishes sensitive business context from generic text.
- Browser extension and network sensor for generative AI monitoring and enforcement.
- Clipboard, file, email, cloud app, USB, network share, and application control policies.
- Policy modes for monitor, review, redact, and block, with simulation before enforcement.

### 3.2 AI-Powered Vulnerability and Risk Management

- Continuous asset discovery and software inventory.
- CVE ingestion enriched with EPSS, CISA KEV, exploit availability, compensating controls, and business criticality.
- AI report generator for executive summaries, technical details, remediation playbooks, and breach-scenario analysis.
- Human risk analytics that correlate user behavior with technical exposure.
- Compliance evidence mapping for GDPR, HIPAA, SOC 2, NIST CSF 2.0, and ISO 27001.

### 3.3 Agentic Incident Response

- Investigation agents that correlate endpoint telemetry, DLP events, user context, asset criticality, and threat intelligence.
- Natural-language incident reports with timeline, scope, likely root cause, confidence, and recommended response.
- Slack and Teams notifications with one-click actions such as approve isolation, deploy patch, escalate to MDR, and acknowledge.
- Automated containment and remediation playbooks with human-in-the-loop approval gates.
- Complete audit trail for every recommendation, approval, and executed action.

### 3.4 Management Console, MSP Control Plane, and AI Copilot

- Modern MSP-first console for company onboarding, licensing, account administration, endpoint inventory, alert triage, DLP scanning, policy editing, and investigation review.
- Clear hierarchy: Platform Owner manages MSP Partners; MSP Partners manage their own Companies and company users; Company roles are scoped to assigned companies.
- Accounts module with Full Name, Email, Status, Role, 2FA, Password expiration, Account lockout, and Company list view; filters for identity, role, status, company with recursive scope, 2FA, password expiration, and lockout.
- Add/edit account workflow with role-aware company assignment, Manage/Edit/View module permissions, 2FA enforcement, and password policies.
- Companies + Licensing hub with Core endpoint licensing, subscription-aware add-ons, AI Efficiency Score, white-label partner controls, and a direct path from company creation to policy assignment to customized installer generation.
- Natural-language query interface for questions such as: "Show endpoints with unpatched Log4j and high user risk."
- Policy-as-code editor with live simulation and impact preview.
- RBAC, SSO with SAML/OIDC, tenant isolation, audited support impersonation, and full API access for SIEM, SOAR, RMM, PSA, and billing systems.

## 4. Technical Architecture

### 4.1 High-Level Components

- Endpoint agent: Rust core with OS-specific collectors and enforcement modules. Linux uses eBPF where appropriate, Windows uses ETW and service integrations, and macOS uses Endpoint Security APIs.
- API backend: FastAPI for AI/DLP workflows and Go services for high-throughput ingestion paths as the system scales.
- Policy engine: Versioned policy model with simulation, staged rollout, rollback, and hot-reload support.
- Data layer: PostgreSQL for authoritative state, Redis for cache and queues, and Qdrant or Pinecone for vector search.
- LLM gateway: Provider abstraction for OpenAI, Anthropic, Grok, Azure OpenAI, or self-hosted vLLM/Ollama deployments.
- Frontend: React/Next.js with TypeScript, focused operator workflows, and accessible enterprise UI patterns.
- Observability: OpenTelemetry, Prometheus, Grafana, Loki, structured audit logs, and cost telemetry for LLM usage.

### 4.2 Recommended Stack

| Layer | Primary choice | Rationale |
| --- | --- | --- |
| Agent core | Rust plus OS-native telemetry APIs | Memory safety, low overhead, and cross-platform portability. |
| Detection | Presidio-compatible scanner plus semantic classifier | Deterministic PII detection plus contextual understanding. |
| Backend | Python/FastAPI plus Go where throughput requires it | Fast AI iteration with a path to high-scale ingestion. |
| Orchestration | LangGraph or CrewAI plus LiteLLM-style gateway | Agentic workflows and provider abstraction. |
| Data | PostgreSQL, Redis, Qdrant | ACID state, queue/cache layer, and semantic search. |
| Frontend | React/Next.js, TypeScript, Tailwind-style system | Strong operator UX and maintainable component model. |
| Infrastructure | Kubernetes, Terraform, Argo CD | GitOps, scale, and portable enterprise deployment. |
| Observability | OpenTelemetry, Prometheus, Grafana, Loki | Full-stack visibility with cost-effective tooling. |

## 5. Repository Starting Point

This repository now contains a Phase 0 skeleton plus the first MSP console foundation slice.

- `apps/api`: FastAPI service with DLP scanning, endpoint heartbeat ingestion, signed policy documents, policy simulation, audit logging, tenant/customer onboarding, enrollment, installer metadata, and Quick Deploy links.
- `apps/console`: React/Vite MSP console wired to live API endpoints for operations, alerts, active policy, manual DLP scans, policy simulation, Companies + Licensing customer creation, policy-to-installer deployment, and Quick Deploy. It also contains the Accounts hierarchy foundation, permission matrix, and full navigation model.
- `agent`: Rust endpoint agent skeleton that reads installer profiles, enrolls with tenant-bound bootstrap tokens, fetches assigned policy packages, and emits nonce-bound HMAC heartbeats.
- `docs`: Product and implementation planning artifacts.

The current codebase is enough to support a focused proof-of-concept sprint, but it is not yet production security software. The next work should add persisted accounts, subscription entitlements, realistic security event simulation, tenant-scoped query enforcement, packaging artifacts, authentication/RBAC, impersonation audit, and threat modeling before adding production enforcement surface area.

## 6. Development Roadmap

### Phase Overview

| Phase | Duration | Key deliverables | Team size |
| --- | --- | --- | --- |
| 0 - Foundation and MVP | Weeks 1-8 | Core DLP agent, Presidio-compatible scanner, basic console, policy engine | Tech lead, 3 backend/agent, 1 frontend |
| 1 - AI Deep Dive | Weeks 9-14 | Semantic DLP, GenAI guardrails, AI vulnerability report generator, partner hierarchy | Add 1 AI/ML engineer |
| 2 - Autonomous IR | Weeks 15-22 | Agentic investigation, smart notifications, playbooks, containment, partner portal v1 | Add 1 backend and 1 security engineer |
| 3 - Production Hardening | Weeks 23-28 | Performance tuning, multi-tenant hardening, SOC 2 prep, pen testing, air-gapped path | Full team |
| 4 - GA and Scale | Weeks 29-36 | MDR integration, marketplace listings, customer onboarding, v1.0 launch | Full team plus support |

### Phase 0 MVP Plan

Weeks 1-2:

- Finalize monorepo standards, local development workflow, CI, linting, formatting, and dependency update automation.
- Define threat model and security boundaries for agent, API, console, policy engine, and telemetry ingestion.
- Harden Rust heartbeat contract, add replay protection, and define signed payload verification. Initial nonce-bound HMAC path is implemented.
- Add API persistence for endpoints, alerts, policies, customers, installers, enrollments, and audits. Initial Postgres-backed POC path is implemented.

Weeks 3-4:

- Integrate Presidio or compatible recognizers with deterministic fallback for offline local development.
- Add custom keyword, regex, and exact-data-match policy definitions.
- Build policy editor and simulation workflow in the console.
- Add automated API and console tests for DLP scan outcomes and policy decisions.

Weeks 5-6:

- Add first local enforcement experiments: alert-only, review, and block decisions for controlled demo flows.
- Package the agent for Linux and macOS development machines, with Windows packaging design captured for follow-up.
- Add basic auth, RBAC boundaries, and tenant-aware query enforcement. Tenant-aware data model scaffolding is implemented.
- Add demo seed data and repeatable scripts for sales-engineering and design-partner walkthroughs.

Weeks 7-8:

- Run performance tests on representative machines and record CPU, memory, network, and latency baselines.
- Execute end-to-end tests across agent heartbeat, DLP scan, alert creation, policy state, and console triage.
- Prepare alpha documentation, operator guide, API reference, and design-partner feedback templates.
- Ship alpha to 3-5 friendly customers or internal pilot groups.

### Phase 0 Acceptance Criteria

- Text samples containing email, phone, credit-card-like data, secrets-like strings, and customer-defined terms return detections with entity type, confidence, location, and policy action.
- Console renders endpoint health, risk score, open alerts, active policy, and manual scan results from live API calls.
- Agent emits signed heartbeat payloads locally and can post them to the API.
- API rejects invalid heartbeat signatures and records accepted heartbeat state.
- Policy changes can be simulated before enforcement and have a versioned audit trail.
- Demo environment can be started from documented commands by a new engineer in under 30 minutes.

## 7. Resource Plan

| Role | Count | Key responsibilities |
| --- | --- | --- |
| Technical lead / architect | 1 | Architecture, agent design, security reviews, roadmap ownership. |
| Backend / platform engineers | 3 | API, policy engine, integrations, ingestion, LLM orchestration. |
| Agent / systems engineers | 2 | Rust core, OS collectors, enforcement, packaging, performance. |
| AI / ML engineer | 1 | Presidio extensions, semantic classifier, prompts, evaluation harness. |
| Frontend engineer | 1 | Console, AI copilot UX, design system, accessibility. |
| Security engineer | 1 shared | Threat modeling, pen test coordination, compliance evidence. |
| DevOps / SRE | 1 shared | CI/CD, Kubernetes, observability, cost control, on-call readiness. |

The team can begin with 6-7 people for Phase 0 and scale to 8-10 people before autonomous response and production hardening.

## 8. Budget Estimate for First 12 Months

| Category | Estimate |
| --- | --- |
| Personnel | USD 1.4M-1.8M |
| Cloud and LLM usage | USD 80k-120k |
| Security tooling, compliance audit, pen tests | USD 60k-90k |
| Marketing, design, legal setup | USD 40k-60k |
| Contingency | Approximately USD 250k |
| Total year-one budget | USD 1.8M-2.3M |

## 9. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| LLM hallucinations in reports | Use RAG over verified CVE data, structured outputs, source citations, confidence scoring, and human review gates for high-severity recommendations. |
| False positives in semantic DLP | Evaluate against golden datasets, keep deterministic fallback rules, add explainability, and support monitor/review modes before block. |
| Adversarial attacks on classifiers | Run adversarial testing, sanitize inputs, use ensemble scoring, and record bypass attempts for model and rule updates. |
| Data privacy concerns | Offer local inference, self-hosted deployments, explicit telemetry controls, and no training on customer data without opt-in. |
| Endpoint performance regression | Maintain strict CPU/memory budgets, benchmark every release, and use staged rollout with rollback. |
| Supply-chain compromise | Generate SBOMs, use dependency scanning, pin critical dependencies, sign builds, and support reproducible release paths. |
| Automation causing operational harm | Require approval gates for destructive actions, policy simulation, scoped permissions, and immutable audit logs. |

## 10. Compliance Roadmap

- Months 1-2: Threat model, data inventory, logging policy, secure SDLC, dependency management, and privacy-by-design review.
- Months 4-5: GDPR and CCPA readiness, DPIA, DPA templates, consent flows, and data deletion workflows.
- Months 6-7: SOC 2 Type I controls implementation, evidence collection, access reviews, and audit kickoff.
- Months 9-10: SOC 2 Type II and ISO 27001 scoping for v1.1.
- Future: HIPAA BAA template, FedRAMP Moderate pathway, and regulated sovereign deployment packages.

## 11. MSP Partner Ecosystem Strategy

Bitdefender has a mature MSP ecosystem with multi-tenant hierarchy, usage-based licensing, MDR resale, RMM/PSA integrations, and a large partner network. Aetherix should compete by being MSP-native and AI-native from the start.

### MSP Advantages

- Full white-label experience across console, agent, reports, portal, notifications, and customer-facing PDFs.
- Simple usage-based pricing with high base margins and clear tier benefits.
- Agentic AI workflows that reduce Level 2 and Level 3 ticket volume.
- MDR as an optional overlay so MSPs can run their own SOC, use a hybrid model, or escalate to Aetherix partners.
- Open RMM/PSA API and webhooks that do not require a narrow vendor ecosystem.
- Sovereign and self-hosted options for regulated MSP clients.

### Partner Roadmap Adjustments

- Phase 1: Complete partner multi-tenant hierarchy, persisted Accounts, Companies + Licensing, and self-service onboarding portal as a parallel track.
- Phase 2: Add full white-label theming, Partner Portal v1, subscription entitlement enforcement, open RMM API, and outbound webhooks.
- Phase 3: Add partner analytics, AI Efficiency Score trends, per-customer profitability, upsell recommendations, MDR handoff tools, SLA tracking, and sovereign deployment package.

### Account Hierarchy Recommendation

| Role | Scope | Companies | Accounts | Licensing | Impersonation |
| --- | --- | --- | --- | --- | --- |
| Platform Owner | All MSP partners and companies | Manage all | Manage all | Manage all | Any partner or company, audit required |
| MSP Partner | Own partner tree | Create and manage own companies | Manage own company users | Manage own subscriptions and add-ons | Own companies only, audit required |
| Company Administrator | Assigned company | View/manage own company operations | Manage company users | View entitlements | No |
| Company Technician | Assigned company | View | No | No | No |
| Company Viewer | Assigned company | View | No | No | No |

Hard rules:

- MSP Partners cannot see or manage other MSP Partners' companies.
- Company users see only their assigned company.
- Platform Owner support impersonation must be explicit, time-bounded, and written to the audit log.
- Permissions are module-specific and should use `Manage`, `Edit`, `View`, or `None` levels.

### Partner Success Metrics

- At least 60% of year-two revenue from MSP/MSSP channel.
- Partner NPS and retention rate tracked quarterly.
- Average MSP support tickets per 100 endpoints materially lower than incumbent baseline.
- White-label adoption rate tracked by partner tier.
- Time to onboard a new customer tenant under 15 minutes for standard MSP workflow.

## 12. Go-to-Market and Packaging

### Target Segments

- Primary: Mid-market organizations with 200-2,000 employees in finance, healthcare, legal, technology, and other data-sensitive sectors adopting generative AI.
- Secondary: Enterprises seeking alternatives to geopolitically constrained or legacy endpoint vendors.
- Channel: MSPs, MSSPs, and MDR providers seeking white-label or co-managed endpoint security.

### Pricing Direction

- Starter: USD 4-6 per endpoint per month for core DLP, basic console, and community support.
- Professional: USD 9-12 per endpoint per month for AI features, vulnerability reports, IR playbooks, and email or Slack support.
- Enterprise: Custom pricing for on-prem, sovereign, white-label, custom integrations, dedicated success, and high-scale support.
- MDR overlay: Additional USD 15-25 per endpoint per month for managed detection and response.

### Launch Strategy

- Beta at Month 4 with 10-15 design partners, including 8-12 MSP partners where possible.
- GA at Month 9 with targeted partner campaigns, focused case studies, and MSSP co-marketing.
- Year 2 target of USD 2M ARR through partner-led motion and selective enterprise sales.

## 13. Success Metrics

### Technical KPIs

- Detection efficacy above 99.7% on agreed MITRE ATT&CK and GenAI exfiltration test suites.
- Agent overhead below 1% average CPU and below 50 MB average memory on Windows 10 reference hardware.
- Simulated incident MTTR below 5 minutes from alert to containment recommendation.
- API p95 latency below agreed thresholds for scan, heartbeat, policy fetch, and alert workflows.
- Policy rollout success above 99.5% across 100-endpoint pilot.

### Business KPIs

- First 12 months post-GA ARR of USD 800k-1.2M.
- Net revenue retention above 110%.
- Pilot and early-customer NPS above 45.
- Support ticket volume below 0.8 per 100 endpoints per month.
- Three enterprise design partners live before GA.

## 14. Immediate Next Steps

1. Run a 2-day technical deep-dive workshop to validate architecture, MVP scope, threat model, and design-partner requirements.
2. Complete a 2-week proof-of-concept sprint using the existing Rust agent, FastAPI service, and React console.
3. Add persistent API state, scanner tests, heartbeat verification tests, and console build validation.
4. Define hiring plan for Rust systems, backend platform, AI/ML, and frontend roles.
5. Start legal and compliance work: entity setup, trademark review, privacy policy, DPA template, and security control register.
6. Identify 5-8 direct design partners and 8-12 MSP design partners for closed alpha and beta feedback.

## 15. Current Development Priorities

The next development loop should build on the implemented MSP console foundation rather than expanding randomly.

1. Persist the MSP hierarchy: partners, accounts, account-company assignments, roles, role permissions, subscriptions, subscription entitlements, partner branding, and impersonation sessions.
2. Add tenant-scoped authentication/RBAC middleware so all reads and writes are explicitly partner/customer bounded.
3. Replace console-only Accounts and Licensing demo state with API-backed list/create/update flows and audit records.
4. Add security event simulation tables and APIs: `telemetry_events`, `security_alerts`, `incident_cases`, and `/simulate/*` routes.
5. Implement scenario generators for GenAI DLP paste, phishing click, USB copy, process anomaly, ransomware behavior, and vulnerability scan.
6. Wire the console to a customer-scoped simulation workspace showing events, alerts, incident timeline, and recommended response.
7. Replace installer metadata-only builds with real package assembly stubs: MSI/EXE, PKG, DEB, and RPM output directories plus signing-status tracking.
8. Add AI risk report generation as structured deterministic templates first, then LLM gateway integration after provider abstraction, budget caps, and prompt audit exist.
9. Build Policy Engine v2 from [docs/policy-engine.md](policy-engine.md): subscription entitlements, modular policy documents, inheritance, validation, templates, and dynamic console sections.

Acceptance criteria for the next module:

- A developer can create a customer, generate a Quick Deploy link, enroll an endpoint, trigger at least three simulated incidents, and view resulting alerts from the console.
- Platform Owner, MSP Partner, and Company user scopes can be represented in persisted account records and enforced by API tests.
- Licensing entitlements can distinguish Core features from add-ons before a policy or console section is enabled.
- Simulation routes create durable events and alerts under the correct customer.
- Alert records include category, confidence, recommended action, policy package id, and a concise AI-ready summary field.
- Tests cover each scenario route and prove cross-customer data is not returned by customer-scoped APIs.

## 16. Two-Week Proof-of-Concept Slice

The immediate repo-level slice is intentionally smaller than the full platform.

Week 1:

- Stabilize local development and CI for API, console, and agent.
- Add tests for DLP scanner behavior and API policy decisions.
- Persist endpoints, alerts, policies, and scan records.
- Verify signed agent heartbeat ingestion and rejection paths.

Week 2:

- Add policy simulation and basic editor workflow in the console.
- Add repeatable demo data and seed commands.
- Add basic performance measurements for agent heartbeat and scanner calls.
- Document alpha demo path and acceptance checklist.

This proof-of-concept should answer the highest-risk early questions: whether the agent can stay lightweight, whether DLP decisions are useful enough for operators, and whether the console can express policy and triage workflows without turning into a full XDR product too early.
