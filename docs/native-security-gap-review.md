# Native Security Coverage Gap Review

Status: active coverage review, May 2026. Companion to [architecture.md](architecture.md) and [poc-plan.md](poc-plan.md).

This document compares the GravityZone + Wazuh-style deployment brief against Aetherix's current repository state and native product roadmap. It is a planning checklist, not an integration plan. Aetherix's product direction remains one signed agent, one tenant-scoped control plane, native AV/EDR + SIEM/HIDS + DLP, and a built-in Compliance Evidence Engine.

The policy-level version of this checklist is [default-policy-v1.01.md](default-policy-v1.01.md). Use it when implementing policy schemas, default templates, module entitlements, and deployment profiles.

## Summary

| Capability area | Aetherix has now | Still needed for future deployment |
| --- | --- | --- |
| Unified console | MSP console foundation, Companies + Licensing, Accounts hierarchy, endpoint/alert/policy views | Permission-driven navigation, persisted auth/session UX, production role scoping, coverage dashboards for AV/EDR, SIEM/HIDS, DLP, and compliance exports |
| Single agent | Rust enrollment client, tenant-bound install profiles, signed nonce heartbeats, policy pull | OS collectors/enforcement modules, tamper protection, signed release pipeline, auto-update, package assembly, endpoint self-protection |
| Machine learning / antimalware | AI settings, semantic gateway edge, deterministic DLP; Rust agent now has YARA-X scanning with cache, IOC matching, ransomware canary/entropy/mass-write detection, process tree rules, Argon2id-backed quarantine with list/restore primitives, and policy-gated quarantine/kill/isolate response evidence for local and remote actions | Broader signature feed, cloud reputation, PE/script inspection depth, ML scoring of unknown PE/scripts after deterministic baselines |
| Web protection | GenAI destination detection in DLP path; MV3 extension foundation; local browser bridge for policy/evidence | Real-site extension validation, managed deployment packaging, URL/domain reputation, anti-phishing, SSL/TLS inspection strategy, broader upload/download enforcement, Search Advisor equivalent if desired |
| Risk analytics | Companies + licensing foundation; DRP/EASM/vulnerability roadmap; AI summary plumbing | Software inventory, CVE/EPSS/KEV enrichment, CIS benchmarks, misconfiguration checks, risk scoring, remediation guidance, executive risk reports |
| Content and device control | Deterministic DLP scan API, policy documents, policy simulation, semantic DLP/GenAI modules, agent event evaluation, DLP evidence route | Broader endpoint file/upload/email/USB/print/screenshot enforcement, managed app/website policy, device inventory, durable label propagation, exception workflow |
| Behaviour monitoring | Heartbeat signals, simulation event store, audit trail, process tree monitoring, suspicious process-chain alerts, and policy-gated process termination evidence | syscall/eBPF stream, ETW/ESF telemetry, deeper behaviour rules, endpoint timeline |
| Firewall and network attack defense | Network isolation intent is now recorded as auditable EDR response evidence | Host firewall policy model, bidirectional rules, network attack detection, brute-force and credential-theft detections, platform firewall enforcement |
| Anti-exploit | Planned in AV/EDR scope | Exploit-chain telemetry, memory/process behaviour detections, script abuse detections, prevention policy, post-detection investigation summaries |
| Ransomware mitigation | Canary files, entropy detector, mass-write detector, policy-gated quarantine/isolation evidence, remote action evidence, and compliance tagging through EDR heartbeats | Rapid process containment expansion, secure backup/snapshot integration, rollback workflow |
| Log management / HIDS | Audit log, telemetry/security alert tables, simulation routes, agent FIM events, inventory, and CIS checks | Agent log collectors, parser library, rootkit checks, correlation rules, MITRE ATT&CK mapping, retention/search, active response gates |
| Compliance evidence | v0 implemented: control catalogue, `evidence_controls`, signed JSON export | Full framework catalogues, scheduled control reviews, attestation workflow, PDF export, evidence object storage, auditor-facing report UX |

## Detailed GravityZone-style Capability Mapping

| Source capability | Aetherix current state | Aetherix future development requirement | Deployment notes |
| --- | --- | --- | --- |
| Local and cloud ML, antivirus, antimalware | Native deterministic AV/EDR v0 exists in the Rust agent: YARA-X scanning/cache, IOC matching, ransomware canary/entropy/mass-write rules, process tree rules, Argon2id-backed reversible quarantine, and policy-gated quarantine/kill/isolate response evidence for autonomous and queued remote actions. | Expand signatures/reputation, PE/script inspection, richer behaviour rules, and later ML scoring. | Cloud reputation and ML must remain advisory or have deterministic fallback evidence. |
| Web protection, anti-phishing, safe browsing | DLP can detect GenAI sink context for submitted text. The MV3 extension and local bridge foundation exist, with unit tests and bridge fallback. | Validate real GenAI sites, add managed extension deployment, URL reputation, phishing detection, upload/download coverage, and destination-aware DLP policy UX. Decide whether SSL inspection is in scope or replaced with endpoint/browser event inspection. | Avoid becoming a network MITM product in v1 unless certificate management and privacy controls are designed. |
| Risk analytics and vulnerability guidance | Product roadmap covers vulnerability reporting; no production inventory/vuln engine yet. | Add software inventory collectors per OS, package ecosystem inventory, CVE/CPE matching, EPSS/KEV enrichment, CIS checks, and customer-specific risk scoring. | This should feed the same incident graph and Compliance Evidence Engine, not a separate reporting island. |
| Content and device control | DLP scanner, policy documents, policy simulation, semantic DLP/GenAI modules, agent event evaluation, local bridge, evidence events, and signed audit exist. Durable sensitivity labels are planned. | Add label schema, label propagation, broader endpoint enforcement for file/upload/email/USB/print/screenshot, website/app allow/block policy, and exception review. | This is the closest area to the current product; extend from current DLP rather than starting a separate control module. |
| Behaviour monitoring / Zero Trust process response | Process tree collection and suspicious parent/child rules now emit EDR events; promoted policy can terminate a target process with structured evidence. | Add syscall/eBPF/ETW/ESF events, more command/script rules, and endpoint timelines. | Automatic termination is policy-gated and auditable; default new rules to monitor/review. |
| Firewall and network attack defense | Isolation actions record intent and evidence, but do not yet modify firewall state. | Add host firewall configuration model, network flow telemetry, brute-force detection, credential-theft indicators, attack signatures, and platform firewall enforcement. | Keep firewall policy separate from DLP policy sections but delivered in the same signed policy package. |
| Anti-exploit and zero-day prevention | Planned only. | Add exploit-behaviour detections around process injection, suspicious child processes, script abuse, memory protection signals where OS APIs allow, and exploit-chain summarization. | Do not promise kernel-mode exploit prevention until signed driver/system extension work is staffed. |
| Ransomware mitigation and recovery | Canary file monitoring, entropy detection, mass-write detection, policy-gated quarantine/isolation evidence, and quarantine restore primitive exist. | Add containment tuning and rollback via VSS or filesystem snapshots where supported. | Restore is limited to agent quarantine artifacts; broader ransomware rollback depends on OS snapshot integration and must be tested under destructive-file simulations. |
| Advanced threat security / tunable ML | AI settings and provider plumbing exist; no endpoint ML model yet. | Add per-tenant model selection, tunable detection thresholds, offline-safe local model/cache, explainable ML scores, and deterministic fallback decisions. | Keep ML additive. Compliance evidence should cite rule/scanner/event facts, not just model output. |
| XDR correlation and response | Incident graph and agentic IR are planned; simulations create telemetry, security alerts, and incident cases. | Normalize endpoint, DLP, SIEM/HIDS, DRP, EASM, and threat-intel events into one graph; add human-approved response actions and timeline generation. | Aetherix should not become a full SOAR in v1. Cross-system orchestration stays manual until v2. |
| Patch management | Not implemented. | Decide whether to build patch deployment or stop at vulnerability detection plus remediation guidance. If built, add OS-specific patch inventory and staged rollout controls. | Recommended v1 stance: inventory and guidance first, patch orchestration later. |
| Integrity monitoring | Planned inside SIEM/HIDS. | Add file integrity monitoring rules, watched paths, baseline hashes, drift detection, and evidence tagging. | This should be part of native SIEM/HIDS v0 and mapped to ISO A.8.15 / A.8.16 / A.8.32. |
| Virtualized environment security | Not implemented. | Add virtualization/cloud workload inventory, VM/container metadata, cloud connector ingestion, and tuned policies for server workloads. | Treat as a later deployment profile, not a separate product family. |
| Mobile security | Not implemented. | Decide whether mobile is in scope. If yes, plan MDM/UEM integration, mobile threat telemetry, and device compliance posture. | Recommended: document as out of v1 unless a specific MSP customer requirement appears. |
| Wazuh-style log management / HIDS | Audit log and basic telemetry tables exist; native SIEM/HIDS is planned. | Add log collectors, parser/rule packs, FIM, rootkit checks, active response gates, local/cloud deployment modes, and retention/search. | Wazuh import can be a read-only migration aid, but runtime detection should be native. |

## Native Development Priorities

1. **Compliance Evidence Engine v0.5.** Expand from signed JSON export to control review workflow, attestation records, PDF export, and object-store evidence references.
2. **Native DLP enforcement v0.** Add sensitivity labels, endpoint/browser enforcement, and label-aware destination policy around the existing DLP and policy-document spine.
3. **Native SIEM/HIDS v0.** Implement log/FIM collectors, parser rules, MITRE mapping, software inventory, and CVE/EPSS/KEV enrichment.
4. **Native AV/EDR v0.** Implemented first slice: YARA-X scanning/cache, IOC matching, process tree rules, ransomware canary/entropy/mass-write detection, reversible quarantine with Argon2id KDF metadata and manifest hash chain, quarantine list/restore primitives, process kill, isolation-intent evidence, and consistent remote action evidence. Next: richer signatures, platform firewall enforcement, rollback, and broader OS telemetry.
5. **Correlation and incident graph.** Normalize AV/EDR, SIEM/HIDS, DLP, DRP, EASM, and audit events into one tenant-scoped investigation graph.
6. **AI layers.** Add semantic classification, alert noise reduction, behavioural baselining, control narratives, and investigation summaries only after deterministic baselines produce standalone evidence.

## Deployment Packaging Notes

- The single signed agent should always include all module code; entitlements and policy packages decide what is active per customer.
- Policy packages should contain separate sections for `edr`, `siem_hids`, `dlp`, `web_protection`, `firewall`, `device_control`, and `compliance_evidence`.
- Every emitted event should carry tenant context, module, detector/rule id, policy version, source endpoint, and `evidence_controls`.
- New detections ship in `monitor` mode first, then move to `review` or `block` only after simulation and operator approval.
- Read-only GravityZone, Defender, and Wazuh connectors may be useful during migration, but they should import history and asset inventory only. They should not become runtime dependencies.
- Pricing should remain subscription-gated rather than code-gated: one binary, one control plane, one evidence chain, with module entitlements declared in customer policy/licensing.

## What Aetherix Should Not Claim Yet

- Kernel-mode antivirus parity.
- Full SOAR orchestration.
- Mobile security management.
- Automated patch deployment.
- SSL interception at network gateway level.
- Proprietary antimalware signature network.

These can be roadmap items or deployment profiles, but they should not appear as delivered capabilities until the agent, control plane, tests, and evidence exports prove them.

## Recently Closed Gaps (post-milestone update)

The items below have moved from "still needed" into "covered, with caveats". They are reproduced here so the gap review stays honest about the current credible claim surface.

- **Impersonation lifecycle with hash-chained evidence.** `apps/api/app/services/impersonation.py` plus the three routes in `app/main.py` provide start / end / list endpoints. Every transition writes an `audit_log` row and an `evidence_events` row tagged with `iso27001-2022:A.5.18` and `soc2-2017:CC6.3`. 6 dedicated tests in `apps/api/tests/test_impersonation.py`, full slice 58 passing. Cross-actor end is forbidden unless the caller is the original impersonator or a platform owner.
- **Signed installer pipeline (CI-gated).** `agent/packaging/macos-package-and-notarize.sh`, `agent/packaging/windows-sign.ps1` + `agent/packaging/windows/Product.wxs`, `agent/packaging/linux-package-and-sign.sh`, and `.github/workflows/release-agent.yml` cover universal macOS notarization, WiX 4 + AzureSignTool (federated OIDC, no long-lived secrets), and `dpkg-sig` builder-signed `.deb`s. The pipeline is wired but no public signed binary has been released — the "first design-partner installs without OS warnings" exit criterion still requires a live release.
- **Policy v2 EDR / EASM / DRP module activation.** `policy_v2_runtime.py` carries module impact functions, `MODULE_EVIDENCE_TAGS`, and a destructive-action list including `quarantine` and `kill`. Licensing addons for DRP / EASM / threat_intelligence are available across all SKUs, gated at runtime. 12 tests in `test_policy_v2.py`.
- **MV3 extension hardening for live GenAI sites.** `apps/extension/utils/site_context.js` extracts per-site `{site, host, path, conversation_id, model, route}` for ChatGPT / Claude / Gemini / Copilot; a shadow-DOM observer + location-change watcher + composer-submit safety net (debounced by sha256 hash) means paste / drop / Enter / send-click all go through `decideAndEmit` with a `destination_context`. 22 unit tests pass. Live-site validation still requires a manual run against the checklist in `docs/extension-validation-checklist.md`.
- **Console permission gating + executed-vs-staged badges.** `apps/console/src/permissions.ts` is the single source of permission checks shared with `App.tsx`. `StagedActionBadge` distinguishes `staged` / `awaiting_approval` / `executed` / `failed` / `denied` from the server-emitted `StagedAction.status` (sourced from real `ModuleActionResult`), so operators cannot mistake a staged action for one that has touched a host. 9 new vitests, 20 total console tests passing.
- **Full remote EDR quarantine management (agent + control plane + console).** Agent 1 delivered `quarantine_list`/`quarantine_restore` with `QuarantineListItem` (including `can_restore`, severity/approval hints), Argon2id manifests, and rich `ResponseEvidence`/`decision_trace`. Agent 3 shipped the complete operator surface (`/endpoints/{id}/quarantine-*` routes, severity-gated approval with dual-operator enforcement, global `/quarantine-restores/pending`, inventory table, response-actions history) plus compliance evidence differentiation for the full lifecycle. Agent 2 wired `QuarantinePage` (live inventory, interactive global Approvals Inbox with approve/deny + self-approval guards, StagedActionBadge integration) and AntimalwareBehavior. Authoritative contract: `docs/console-wiring-remote-edr.md`. All tests green; this is now a production-intent, auditable, multi-tenant remote response workflow.

### What Still Stays in "Should Not Claim Yet"

Even with the above, the following still require live evidence before sales claims:

- Signed binary release is CI-ready but no public artifact is published — do not claim "deploys cleanly on Windows / macOS / Linux without warnings" until a tag has been signed end-to-end and verified on a clean host per the local verification commands in `docs/installers.md`.
- EDR / EASM / DRP module activation is **semantic** — the agent's deterministic enforcement loop is the source of truth for actually executing quarantine / kill / isolate. Until those loops emit `executed` events back through the evidence chain on a real endpoint, the badge taxonomy correctly stops at `staged` / `approved`.
- Live-site MV3 validation against ChatGPT / Claude / Gemini / Copilot still requires human sign-off per `docs/extension-validation-checklist.md`. The code path is exercised by unit tests but real DOM drift is not.
- Compliance Evidence Engine v0.5 (control-review workflow, attestations, PDF export, object-store reference) remains scoped — only the impersonation control mapping shipped in this milestone.
