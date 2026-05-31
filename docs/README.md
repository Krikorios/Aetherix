# Aetherix Docs Guide

Status: active documentation index for the next development phase.

Use this folder in the following order when planning or implementing work:

1. `current-capabilities-snapshot-2026-05-29.md` for what is actually delivered.
2. `roadmap-2026.md` for the prioritized backlog and business sequencing.
3. `architecture.md` for system boundaries, control-plane contracts, and evidence model.
4. `development.md` for local setup, validation commands, and workflow constraints.

## Active Docs

- `current-capabilities-snapshot-2026-05-29.md` — current product truth.
- `roadmap-2026.md` — prioritized engineering roadmap.
- `architecture.md` — platform architecture and authoritative contracts.
- `development.md` — local workflow and validation.
- `policy-engine.md` — policy model and subscription-aware enforcement.
- `console-wiring-remote-edr.md` — console to backend response-management contract.
- `multi-agent-coordination-protocol.md` — delivery model for coordinated work.
- `installers.md` — packaging and deployment flow.
- `opensearch-integration.md` — event search and retention workstream.
- `edr-behavior-anti-exploit-interface.md` — behavior protection interface.
- `edr-ransomware-rollback-interface.md` — rollback interface contract.
- `vss-rollback-provider-plan.md` — Windows rollback provider plan.
- `vss-rollback-provider-tasks.md` — task breakdown for rollback work.
- `vss-rollback-provider-walkthrough.md` — rollback implementation walkthrough.
- `protection-module-template-guide.md` — console module implementation pattern.
- `accounts.md` and `companies.md` — tenant, account, and licensing behavior.
- `agent-semantic-dlp-enforcement.md` and `default-policy-v1.01.md` — DLP and baseline policy references.

## Historical Docs Kept For Context

- `coordination-brief-cycle-2026-05-29.md`
- `coordination-brief-cycle-2026-05-30.md`
- `console-ui-audit-2026-05-28.md`
- `milestone-summary-2026-05-23.md`
- `native-security-gap-review.md`
- `poc-plan.md`
- `regression-hardening-report-2026-05-23.md`
- `extension-validation-checklist.md`

Older full coordination briefs remain useful as historical records when tracing design decisions. The short-form cycle summaries and standalone prompt artifacts were removed because they duplicated the full briefs or no longer represented the active codebase.

## Next Phase Priorities

1. Finish correlation consumption in the protection-module workspace, starting with the Antimalware & Behavior detail panel.
2. Complete DLP to EDR correlation using the new `dlp_events` persistence path and sha256-aware joins.
3. Start rollback Phase 1 implementation: provider trait, no-op provider, and readiness hints.
4. Close the remaining open console audit items that are still marked incomplete.
5. Restore full local validation on a supported toolchain: Python 3.12 or 3.13 for the API, a working npm registry path for console dependencies, and a Rust toolchain for `cargo test`.

## Validation Reality Check

The current documented validation commands are still the right targets, but local execution currently depends on the following environment constraints:

- API dependencies are pinned to versions that do not currently resolve on Python 3.14; use Python 3.12 or 3.13.
- Rust validation requires an installed toolchain; `cargo` was not available in the current environment.
- Console validation depends on a successful `npm install`; network timeouts against the npm registry can block setup.