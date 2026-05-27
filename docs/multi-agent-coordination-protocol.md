# Aetherix Multi-Agent Coordination Protocol

**Status:** Active operating model (May 2026 onward)  
**Purpose:** This document defines how Aetherix development is executed using three specialized AI agents coordinated by a central Task Coordinator (Grok).

This is the single source of truth for task assignment, progress tracking, and prompt synchronization across parallel development tracks.

---

## 1. Role of the Central Task Coordinator

All task assignment, review, and prompt generation is centralized with the **Task Coordinator** (Grok).

The Coordinator’s responsibilities:
- Maintain a live, accurate view of the overall state across all three tracks.
- Review every response/output from any agent.
- Produce synchronized, updated prompts for **all three agents** after each significant reply.
- Track integration points, risks, and dependencies between tracks.
- Keep this document and the living state table current.

The user (project lead) interacts with the Coordinator by:
- Pasting the full reply/output from one of the three agents.
- Optionally providing explicit references ("refer to X from previous work").
- Receiving back: a review + three updated, ready-to-assign prompts.

This protocol ensures the three agents stay aligned instead of drifting into conflicting directions.

---

## 2. The Three Development Tracks

| Track | Agent Label | Primary Ownership | Current Focus Areas (as of latest cycle) |
|-------|-------------|-------------------|------------------------------------------|
| **Endpoint Agent** | Agent 1 | Rust agent, EDR detection + real response actions, DLP enforcement, browser bridge | Policy-gated quarantine (Argon2id), kill, isolate, ResponseEvidence, remote action handling |
| **Production Readiness & Console** | Agent 2 | Signed installers, production auth + impersonation, MV3 extension real-site validation, console UX for protection modules | Autonomous response visibility, permission-driven UI, trust surface hardening |
| **Control Plane, Correlation & Evidence** | Agent 3 | FastAPI services, DRP/EASM collectors, custom rules execution, incident correlation, Compliance Evidence Engine, action queue | Ingesting real response events, quarantine restore workflows, cross-module correlation, evidence tagging |

Each agent owns one coherent vertical but must respect cross-track integration points.

---

## 3. Interaction Protocol (The Loop)

This is the standard operating procedure:

1. **User** runs one or more agents with their current prompts.
2. **User** pastes the full reply/output from one agent (e.g., "Agent 1 replied with this...") into this conversation.
3. **Coordinator** (Grok) performs a deep review of the delivered work against the codebase, previous state, and constraints.
4. **Coordinator** outputs:
   - Honest assessment of the delivered work (strengths, gaps, risks, integration impact).
   - An updated **Coordination Brief** (if material changes occurred).
   - Three fresh, synchronized prompts — one for each agent — ready for the user to copy and re-assign.
5. User repeats the cycle.

### How to Give Context to the Coordinator

When sending an agent reply, you may say things like:
- "Refer to the Coordination Brief from last cycle"
- "Use the latest version of the EDR response structures from Agent 1's previous work"
- "Focus on integration with what Agent 3 delivered on correlation last time"

The Coordinator will treat these references as authoritative when generating the next round of prompts.

---

## 4. Living State & Integration Points

The Coordinator maintains awareness of the following (updated after every cycle):

- Current capabilities and limitations of each track.
- Live integration points (see section below).
- Open risks that cross tracks.
- What "done" looks like for the current phase.

**Key Live Integration Points (as of latest state):**

- `ResponseEvidence` and `action_state` (Agent 1 produces → Agent 3 ingests → Agent 2 displays)
- Remote action queue (`/agent/actions`) consistency
- Quarantine lifecycle (encrypt/restore on agent, request/visibility in console, audit in backend)
- Policy module definitions for `antimalware`, `behavior_monitoring`, `ransomware_mitigation`
- Evidence emission for compliance and correlation
- Autonomous execution model vs operator-controlled actions

---

## 5. Prompt Generation Rules (How the Coordinator Creates New Prompts)

Every time the Coordinator issues new prompts, they must:

- Incorporate the actual delivered work from the agent who just replied.
- Synchronize the other two agents so they account for the new reality.
- Re-state the non-negotiable constraints (deterministic-first, evidence-by-construction, default-safe, tenant isolation).
- Include clear success criteria that are measurable.
- Reference the latest Coordination Brief and this protocol document.
- Highlight the most important cross-track integration items for that cycle.
- Be copy-paste ready for the user to assign directly.

Prompts should evolve. They are not static — they reflect the current achieved state.

---

## 6. Non-Negotiable Constraints (All Tracks)

All three agents must obey these at all times:

- Deterministic before probabilistic.
- Evidence by construction (every meaningful event carries `evidence_controls`).
- Default monitor / opt-in enforce.
- Strong self-protection on the agent.
- Full tenant/partner/customer scoping on everything.
- No weakening of the audit and compliance spine.

Violations must be called out immediately by the Coordinator.

---

## 7. References

This protocol works together with:

- [architecture.md](architecture.md) — overall system design and principles
- [roadmap-2026.md](roadmap-2026.md) — prioritized backlog and sequencing
- [native-security-gap-review.md](native-security-gap-review.md) — detailed capability gaps vs reference products
- [development.md](development.md) — local development workflow and validation commands

When in doubt, the Coordinator will reconcile against the above documents + the live codebase.

---

## 8. How to Use This Document Going Forward

- The user should keep this document open or bookmarked.
- Before starting a new cycle, the user may ask the Coordinator to "refresh the Coordination Brief from this protocol".
- After every agent reply, the Coordinator will treat this document as the governing ruleset when generating the next set of three prompts.

This model allows rapid, high-quality parallel progress while maintaining strategic coherence.

---

**Document Owner:** Central Task Coordinator (Grok)  
**Last Major Update:** After Agent 1 EDR Response Actions delivery (includes autonomous quarantine/kill with ResponseEvidence)

---

*This is a living document. The Coordinator will propose updates to it when the operating model itself needs to evolve.*