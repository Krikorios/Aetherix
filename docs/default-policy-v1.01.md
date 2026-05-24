# Default Policy v1.01

Status: target baseline for future development and deployment planning, May 2026. Companion to [policy-engine.md](policy-engine.md), [architecture.md](architecture.md), and [native-security-gap-review.md](native-security-gap-review.md).

This document translates the GravityZone-style default policy baseline into an Aetherix-native policy target. It should be used as the reference checklist for policy editor design, policy schema work, agent module development, and deployment templates.

Source workbook: [../Default Policy v1.01.xlsx](../Default%20Policy%20v1.01.xlsx). The workbook has one sheet (`Sheet1`) with `Category`, `Sub-category`, and `Setting` columns. This markdown version captures the workbook defaults and adds Aetherix-specific controls that are not present in a traditional endpoint stack: GenAI DLP, tenant evidence tagging, signed policy simulation, Compliance Evidence Engine exports, DRP/EASM, and AI-assisted investigation.

## Policy Principles

1. **Deterministic first.** Every enabled protection must have a rule, scanner, signature, telemetry event, or policy condition that works without AI.
2. **AI is additive.** ML, semantic classification, summaries, and recommendations increase fidelity, but they do not become the sole reason for block/isolate/rollback.
3. **Monitor before enforce.** New modules default to `monitor` or `review`. `block`, `isolate`, and `rollback` require simulation evidence and operator approval.
4. **Subscription-gated, not code-gated.** The signed agent can carry all module code; policy and entitlements decide what runs for a customer.
5. **Evidence by construction.** Every policy decision and detection emits `evidence_controls` for the Compliance Evidence Engine.

## Workbook Baseline Extract

These are the important defaults extracted from `Default Policy v1.01.xlsx`.

| Workbook category | Workbook default | Aetherix interpretation |
| --- | --- | --- |
| General notifications | Silent mode Off, tray icon On, alert pop-ups Off, notification pop-ups Off, endpoint issue visibility On, restart notification Off | Keep endpoint UI quiet by default while preserving operator-visible endpoint health. |
| General settings | Uninstall password On, proxy Off, power user Off, 30-day event retention, crash/suspicious-file/health telemetry On, user login data to GravityZone Off | Map to agent tamper protection, privacy controls, retention policy, and optional cloud lookup. |
| Product and content update | Hourly product and security-content updates, public update fallback On, update ring Slow Ring | Map to agent update channel, rollout rings, and update-source policy. |
| Security telemetry | Off, with process/file/registry/network/logon event types listed as disabled options | Aetherix should start with signed heartbeats and audit, then enable SIEM/HIDS telemetry by entitlement and policy. |
| Antimalware on-access | Normal mode, ransomware vaccine On, scan local/network files, all file types, only new/changed files, boot sectors On, keyloggers/PUA On, archives Off, deferred scanning On | Maps to Aetherix AV/EDR v0 deterministic scanner defaults. |
| Antimalware on-execute | Cloud threat detection On, Advanced Threat Control On, fileless attack protection On, command-line scanner On, ransomware mitigation On, local/remote monitoring On, automatic recovery On | Maps to Aetherix behaviour rules, cloud reputation, anti-exploit, ransomware canary/entropy, and rollback policy. |
| Antimalware on-demand | Full scan every two weeks, CD/DVD and USB scan On, aggressive contextual scan, rootkit/keylogger/PUA checks On | Maps to scheduled on-demand scans and external-device scan profiles. |
| HyperDetect | Off, with targeted attack/suspicious traffic/exploit/ransomware/grayware options available | Treat tunable ML as future add-on/advisory until deterministic scanners exist. |
| Advanced Anti-Exploit | On; Windows process introspection and privilege escalation kill process; LSASS block only; Linux credential/ptrace/namespace/corruption/SUID monitoring report only | Maps to anti-exploit policy with OS-specific actions and conservative Linux report-only defaults. |
| Quarantine | Delete files older than 30 days, submit quarantined files hourly, rescan after updates, copy before disinfect, local user actions On | Maps to quarantine retention, rescan, submission, and local action policy. |
| Sandbox Analyzer | Off / cloud sandbox not available | Treat sandbox as optional future add-on, not v1 core. |
| Firewall | Off, with Wi-Fi monitoring, port-scan blocking, and low log verbosity options visible | Aetherix should model firewall separately and only enable when the customer entitlement/policy requires it. |
| Firewall rules | Several Home/Office allow/deny rules listed for ICMP, RDP, email, HTTP, printing, Explorer FTP/HTTP | Convert to signed host firewall rule schema when firewall module is built. |
| Network protection | On, encrypted traffic interception On, HTTPS/RDP/FTPS/SCP/SSH scan On, browser toolbar/search advisor On, exclusions present | Aetherix should prefer endpoint/browser inspection over network MITM for v1, while preserving URL/domain exclusions. |
| Web protection | Anti-phishing On, fraud/phishing protection On, web traffic scan On, email traffic scan Off | Maps to browser/URL/phishing controls; email traffic scanning is not v1 unless mail-flow scope is added. |
| Network attacks | On; ATT&CK initial access, discovery, lateral movement, crimeware Block; credential access Report Only | Maps to network attack signatures and MITRE ATT&CK-tagged detections. |
| Patch management | No maintenance window selected | Aetherix v1 should inventory and recommend patches before doing patch deployment. |
| Device control | Off; listed device classes are Allowed | Aetherix should build device control as a DLP enforcement module, defaulting to monitor/review before block. |
| Integrity monitoring | Real-time monitoring Off | Aetherix should include FIM in SIEM/HIDS v0 but not claim it as delivered yet. |
| Relay | Automatic discovery Off; update relay settings present | Map to on-prem relay deployment profile and update-source policy. |
| Exchange protection | Antimalware and antispam On, content filtering Off | Treat as out of endpoint v1 unless Microsoft 365 / mail-flow protection becomes a separate module. |
| Encryption | Off | Treat as a future add-on or integration; do not claim current support. |
| Incidents Sensor | On | Maps to endpoint event sensor and incident graph inputs. |
| Storage protection | ICAP on-access scanning On, infected files Deny Access | Treat as a server/storage workload profile, not default endpoint v1. |
| Risk management | On, daily schedule | Maps to software inventory, vulnerability posture, misconfiguration, and remediation guidance. |
| Live Search | Off | Treat as future investigation/search capability after telemetry retention exists. |

## Aetherix Default Policy Summary

This table separates the workbook's current default from Aetherix's target baseline. Some workbook modules are Off but still appear as Aetherix planned modules because the Aetherix product goal is broader native coverage.

| Module | Workbook default | Aetherix target default | Aetherix current state | Future build needed |
| --- | --- | --- | --- | --- |
| General agent controls | Enabled | Enabled, monitor/report | Enrollment, tenant-bound install profile, signed heartbeat, policy pull | Tamper protection, auto-update, agent self-defense, rollout rings |
| Antimalware | Enabled | Enabled, monitor then block known-bad | Not implemented as detector | YARA/signatures, hash reputation, IOC matching, PE/script inspection, quarantine |
| Local/cloud ML | Cloud detection On; HyperDetect Off | Advisory, review high confidence | AI provider settings exist for API-side workflows | Local model/cache, cloud reputation, explainable score, deterministic fallback |
| Web protection | Network/web protection On; email traffic scan Off | Enabled for browser/URL/GenAI, email later | GenAI sink detection in DLP path | Browser sensor, URL reputation, anti-phishing, upload/download controls |
| Risk analytics | Risk Management On daily | Enabled, review remediation | Licensing/company foundation, vulnerability roadmap | Software inventory, CVE/CPE, EPSS/KEV, CIS/misconfiguration checks |
| Content and device control | Web content control On; Device Control Off | DLP enforcement enabled in monitor/review; device block later | DLP scan API and policy simulation | USB/printer/clipboard/file/upload/email/screenshot enforcement, labels |
| Behaviour monitoring | Advanced Threat Control On; Incidents Sensor On | Enabled, review medium, isolate high | Heartbeat risk and simulated security alerts | Process tree, eBPF/ETW/ESF telemetry, suspicious process termination |
| Firewall and network defense | Firewall Off; Network Attack Defense On | Network defense enabled; firewall policy optional | Planned only | Host firewall policy, network telemetry, brute-force and credential-theft detections |
| Anti-exploit | Advanced Anti-Exploit On | Enabled, review/block high confidence | Planned only | Memory/process/script exploit detections and exploit-chain timeline |
| Ransomware mitigation | On, automatic recovery | Enabled, isolate high confidence, rollback with approval | Planned canary/entropy/rollback design | Canary files, entropy delta, mass-write detection, snapshots/VSS rollback |
| SIEM/HIDS and integrity monitoring | Security Telemetry Off; Integrity Monitoring Off | Planned, entitlement-gated | Audit log, telemetry/security alert tables, simulation routes | Log collectors, FIM, rootkit checks, parsers, MITRE mapping, active response gates |
| Compliance Evidence Engine | Not present in workbook | Enabled, tag/export evidence | v0 implemented: catalogue, tags, signed JSON export | Full catalogues, control reviews, attestations, PDF pack, evidence object store |

## Core Module Defaults

### General

```jsonc
{
  "general": {
    "enabled": true,
    "agent_update_channel": "stable",
    "tamper_protection": true,
    "agent_health_reporting": true,
    "privacy_level": "metadata_only",
    "cloud_lookup": true,
    "on_prem_relay_required": false,
    "evidence_controls": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"]
  }
}
```

Current support: signed heartbeats and tenant-bound enrollment exist. Tamper protection and update rings are future agent work.

### Antimalware and ML

```jsonc
{
  "antimalware": {
    "enabled": true,
    "on_access": { "enabled": true, "mode": "monitor", "scan_archives": false, "scan_network_shares": true },
    "on_execute": { "enabled": true, "block_known_bad": true, "review_unknown_high_risk": true },
    "on_demand": { "enabled": true, "schedule": "weekly", "day": "sunday", "time": "03:00" },
    "detectors": {
      "yara": true,
      "signatures": true,
      "hash_reputation": true,
      "ioc_matching": true,
      "pe_script_inspection": true,
      "cloud_reputation": true,
      "local_ml": false
    },
    "response": { "quarantine": true, "kill_process": "review", "isolate_endpoint": "operator_required" },
    "exclusions": []
  }
}
```

Build note: ship YARA/signature/hash/IOC first. ML scoring becomes advisory until deterministic scanners and quarantine evidence exist.

### Web Protection

```jsonc
{
  "web_protection": {
    "enabled": true,
    "anti_phishing": true,
    "url_reputation": true,
    "browser_guardrails": true,
    "ssl_inspection": "not_v1",
    "blocked_categories": ["malware", "credential_theft", "phishing", "newly_registered_domains"],
    "genai_destinations": ["copilot", "claude", "gemini", "chatgpt"],
    "sensitive_paste_action": "review",
    "sensitive_upload_action": "block"
  }
}
```

Build note: prefer browser/endpoint event inspection over network-level SSL interception for v1.

### Risk Analytics

```jsonc
{
  "risk_analytics": {
    "enabled": true,
    "software_inventory": true,
    "cve_matching": true,
    "epss": true,
    "cisa_kev": true,
    "cis_benchmarks": true,
    "misconfiguration_checks": true,
    "business_criticality_weighting": true,
    "risk_scoring": {
      "enabled": true,
      "method": "weighted_average",
      "vulnerability_weights": {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.1
      },
      "epss_threshold": 0.5,
      "kev_boost": 2.0
    },
    "remediation_guidance": {
      "enabled": true,
      "auto_generate_tickets": false,
      "priority_based": true,
      "sla_tracking": true
    },
    "executive_reporting": {
      "enabled": true,
      "frequency": "monthly",
      "include_trends": true,
      "benchmark_against_peers": true
    },
    "default_action": "review_remediation"
  }
}
```

Build note: inventory and risk scoring should feed the incident graph and Compliance Evidence Engine, not a standalone dashboard.

### Content and Device Control

```jsonc
{
  "device_control": {
    "enabled": true,
    "usb_storage": { "default_action": "review", "allow_encrypted_devices": true, "block_unknown_write": true },
    "printer_control": { "enabled": true, "sensitive_document_action": "review" },
    "clipboard_control": { "enabled": true, "sensitive_paste_action": "review" },
    "screenshot_control": { "enabled": true, "restricted_label_action": "review" },
    "approved_devices": []
  },
  "classification_labeling": {
    "enabled": true,
    "labels": ["Public", "Internal", "Confidential", "Restricted"],
    "auto_label_suggestions": true,
    "label_propagation": ["copy", "move", "rename"],
    "restricted_destination_action": "block"
  }
}
```

Current support: DLP scanning and policy simulation exist. Endpoint enforcement and labels are future work.

### Behaviour Monitoring, Anti-Exploit, Ransomware

```jsonc
{
  "behavior_monitoring": {
    "enabled": true,
    "process_tree_analysis": true,
    "lolbin_detection": true,
    "persistence_detection": true,
    "credential_access_detection": true,
    "medium_confidence_action": "review",
    "high_confidence_action": "isolate"
  },
  "anti_exploit": {
    "enabled": true,
    "memory_protection": true,
    "script_abuse_detection": true,
    "office_child_process_block": true,
    "browser_exploit_mitigation": true,
    "high_confidence_action": "block"
  },
  "ransomware_mitigation": {
    "enabled": true,
    "canary_files": true,
    "entropy_delta_detection": true,
    "mass_file_change_detection": true,
    "shadow_copy_or_snapshot_protection": true,
    "auto_isolate_on_high_confidence": true,
    "rollback_approval": "operator_required"
  }
}
```

Build note: destructive actions such as isolate and rollback must be policy-gated, simulated, and audit-backed.

### Firewall and Network Attack Defense

```jsonc
{
  "firewall": {
    "enabled": true,
    "default_inbound": "block",
    "default_outbound": "allow",
    "profiles": ["office", "remote", "untrusted_wifi"],
    "rules": []
  },
  "network_protection": {
    "enabled": true,
    "dns_reputation": true,
    "lateral_movement_detection": true,
    "brute_force_detection": true,
    "credential_theft_detection": true,
    "command_and_control_detection": true,
    "network_attack_signature_action": "review"
  }
}
```

Build note: the workbook has Firewall Off but Network Attack Defense On. Aetherix should preserve that split: network attack detections can ship before host firewall enforcement, and firewall policy belongs in the same signed policy package but remains its own module section.

### SIEM/HIDS and Integrity Monitoring

```jsonc
{
  "siem_hids": {
    "enabled": true,
    "log_sources": ["syslog", "journald", "windows_event_log", "etw", "os_log", "app_logs"],
    "file_integrity_monitoring": true,
    "rootkit_checks": true,
    "software_inventory": true,
    "syscall_stream": "platform_supported",
    "correlation_rules": true,
    "mitre_attack_mapping": true,
    "active_response": "operator_required"
  }
}
```

Build note: Wazuh import may help migration, but the runtime collector and rule path should be native.

## Aetherix Additions Beyond the GravityZone-style Baseline

| Aetherix addition | Default policy treatment | Why it matters |
| --- | --- | --- |
| GenAI DLP guardrails | Enabled in monitor/review for paste, block for restricted uploads | Covers browser AI exfiltration workflows that classic endpoint policy often misses |
| Compliance Evidence Engine | Always enabled for supported events | Turns policy decisions into ISO/SOC/NIST/GDPR/HIPAA evidence automatically |
| Signed policy simulation | Required before promotion to block/isolate/rollback | Reduces MSP false-positive and business-disruption risk |
| Tenant-scoped policy inheritance | MSP default -> customer -> group -> endpoint | Lets MSPs run one baseline while supporting customer exceptions |
| AI-drafted narratives | Advisory only | Speeds reporting without making AI the evidence source |
| DRP/EASM add-ons | Disabled by default, available as licensed modules | Extends endpoint posture into external exposure and brand/identity risk |
| Migration connectors | Disabled by default, read-only only | Helps import GravityZone/Defender/Wazuh history without making Aetherix dependent on them |

## Full Aetherix App Coverage Still Needed

Default Policy v1.01 should become more than an endpoint policy. It should be the customer protection profile that drives the whole Aetherix app: console visibility, entitlements, onboarding, evidence generation, AI use, external risk, reports, and deployment posture.

| App area | Policy/control section to add | Default for v1.01 | Current state | Needed to cover the full app idea |
| --- | --- | --- | --- | --- |
| MSP tenancy and RBAC | `tenant_scope`, `rbac_visibility`, `support_impersonation` | Enabled, least-privilege, impersonation audited | Account hierarchy and role model exist; backend auth/RBAC is partially implemented | Enforce tenant-scoped API reads/writes everywhere, permission-driven nav, audited support impersonation start/action/end |
| Subscription and entitlements | `entitlements`, `module_visibility`, `usage_limits` | Enabled, locked modules visible with reason | Companies + Licensing foundation exists | `subscription_entitlements`, limits per module, policy validation on create/update/assign/promote/effective fetch |
| Customer onboarding and installers | `deployment_profile`, `installer_profile`, `quick_deploy` | Enabled for Windows/macOS/Linux packages | Customer quick-create, installer metadata, Quick Deploy, install profile exist | Real package assembly, signing/notarization, auto-update, deployment rings, relay profile, rollout status |
| Policy inheritance and simulation | `policy_resolution`, `simulation_required_for_enforce` | Enabled; simulation required for `block`, `isolate`, `rollback` | Signed policy docs and DLP simulation exist | `PolicyDocumentV2`, module-level simulation, effective preview, group/endpoint overrides, rollback |
| AI provider governance | `ai_settings`, `ai_budget`, `ai_redaction`, `ai_audit` | Hosted/default where licensed; BYO allowed by entitlement; redact PII before send | Per-company AI providers, encrypted keys, daily quotas, probe route, redaction path exist | Central LLM gateway, prompt/response hash audit, structured outputs, model allowlists, per-module budgets |
| Compliance Evidence Engine | `compliance_evidence`, `control_reviews`, `attestations` | Always enabled for supported events | v0 catalogue, `evidence_controls`, signed JSON export exist | Full framework catalogues, scheduled control reviews, attestations, PDF pack, evidence object storage, auditor portal UX |
| DLP classification and labeling | `classification_labeling`, `semantic_dlp`, `genai_guardrails` | Enabled in monitor/review; block restricted uploads | DLP scan, semantic edge, GenAI context, policy simulation exist | Sensitivity labels, EDM/fingerprints, label propagation, endpoint/browser enforcement, redacted review summaries |
| Native AV/EDR | `antimalware`, `behavior_monitoring`, `anti_exploit`, `ransomware_mitigation` | Planned enabled, deterministic first | Agent transport exists; detector not implemented | YARA/signatures/IOC, process tree, anti-ransomware canaries, quarantine/isolate, exploit detections, rollback workflow |
| Native SIEM/HIDS | `siem_hids`, `integrity_monitoring`, `vulnerability_inventory` | Entitlement-gated, monitor/review | Audit log and simulation event tables exist | Log/FIM/rootkit collectors, parser rules, MITRE mapping, CVE/EPSS/KEV, CIS checks, retention/search |
| Firewall and network defense | `firewall`, `network_protection`, `dns_reputation` | Network defense first; firewall optional | Planned only | Host firewall schema, network flow telemetry, brute-force/credential-theft/C2 detections, URL/DNS reputation |
| DRP | `digital_risk_protection` | Disabled unless licensed; review findings | Roadmap and data contracts exist | Monitored assets, brand/executive/domain/social/repo/paste collectors, phishing/typosquat/leak findings, customer queue |
| EASM | `external_attack_surface_management` | Disabled unless licensed; review findings | Roadmap and data contracts exist | DNS/CT/passive DNS/cloud discovery, safe port scan, asset graph, exposures, cert/vuln findings, shadow IT detection |
| Threat intelligence and takedown | `threat_intelligence`, `takedown_workflows` | Intel review by default; takedown requires approval | Roadmap only | Feed ingestion, indicator validation, campaign correlation, provider/GDN workflows, takedown status tracking |
| Incident graph and response | `incident_correlation`, `agentic_response`, `response_actions` | Human-approved response | Security alerts/incidents simulation exists | Cross-module incident graph, timelines, one-click response, approval gates, customer-ready summaries |
| Reports and MSP value proof | `ai_reports`, `executive_reports`, `white_label` | Monthly draft reports, approval before send | White-label direction and AI summaries exist | Executive/technical report generator, scheduled delivery, risk trend, compliance export links, MSP branding |
| Integrations | `integrations`, `webhooks`, `migration_imports` | Read-only migration imports; outbound webhooks review | Not implemented beyond API foundations | PSA/RMM/SIEM/webhook outputs, GravityZone/Defender/Wazuh import, billing hooks, Teams/Slack notifications |
| Observability and operations | `platform_observability`, `retention`, `backup` | Enabled for platform operators | Basic logs and Postgres exist | OpenTelemetry, metrics, audit retention, backup/restore, queue health, cost telemetry, status page |
| Deployment modes | `deployment_mode`, `relay`, `air_gap` | Cloud first, on-prem/air-gap profiles planned | Deployment mode fields and relay concepts exist | SaaS/MSP-hosted/customer-hosted/air-gapped packaging, relay services, offline updates, object storage options |

## Full Policy Envelope Target

The long-term policy should be one signed envelope with endpoint, cloud-control-plane, and MSP operations sections. Endpoint agents apply only the sections they understand; the control plane uses the rest to drive UI visibility, entitlements, reports, evidence, and integrations.

```jsonc
{
  "schema_version": "2.0",
  "name": "Default Policy v1.01",
  "scope": { "partner_id": null, "customer_id": null, "group_id": null, "endpoint_id": null },
  "lineage": { "parent_policy_id": null, "inheritance_mode": "inherit_with_overrides" },
  "modules": {
    "general": {},
    "tenant_scope": {},
    "entitlements": {},
    "deployment_profile": {},
    "antimalware": {},
    "behavior_monitoring": {},
    "anti_exploit": {},
    "ransomware_mitigation": {},
    "firewall": {},
    "network_protection": {},
    "web_protection": {},
    "classification_labeling": {},
    "semantic_dlp": {},
    "device_control": {},
    "siem_hids": {},
    "integrity_monitoring": {},
    "vulnerability_inventory": {},
    "digital_risk_protection": {},
    "external_attack_surface_management": {},
    "threat_intelligence": {},
    "takedown_workflows": {},
    "incident_correlation": {},
    "agentic_response": {},
    "ai_settings": {},
    "ai_reports": {},
    "compliance_evidence": {},
    "integrations": {},
    "platform_observability": {},
    "white_label": {}
  }
}
```

## App-Wide Evidence Requirements

Every module above should produce evidence that can be exported by customer, framework, control, time range, module, and incident.

| Evidence source | Required fields |
| --- | --- |
| Policy changes | actor, scope, policy version, before/after hashes, simulation result, approval reason, `evidence_controls` |
| Endpoint detections | endpoint id, module, detector id, policy version, action, confidence, deterministic inputs, response action, `evidence_controls` |
| DLP and labels | source, destination, label, entity types, content hash, action, reviewer, redaction status, `evidence_controls` |
| SIEM/HIDS events | source log, parser/rule id, MITRE tags, severity, correlation id, retention bucket, `evidence_controls` |
| DRP/EASM findings | asset id, finding type, source, confidence, evidence ref, remediation, status, `evidence_controls` |
| AI activity | provider, model, tenant setting, prompt/response hashes, redaction flag, quota result, deterministic fallback, reviewer |
| Response actions | action type, requested by, approved by, executed by, target, result, rollback availability, chain hash |
| Compliance reviews | control id, owner, status, reviewer, attestation text, evidence refs, export signature |
| Reports | audience, generated by, reviewed by, included modules, evidence refs, delivery status |

## Workbook Modules To Treat As Later Profiles

| Workbook module | Aetherix stance |
| --- | --- |
| Exchange Protection | Not endpoint v1. Consider later Microsoft 365 / mail-flow security module or integration. |
| Storage Protection / ICAP | Server/storage workload profile after endpoint modules mature. |
| Relay | Deployment infrastructure profile for on-prem and bandwidth-controlled customers. |
| Encryption | Future add-on or managed integration; do not claim current support. |
| Sandbox Analyzer | Optional advanced threat add-on after AV/EDR deterministic scanning exists. |
| Live Search | Future investigation/search feature after telemetry retention and query indexing exist. |
| Patch Management | Start with inventory and remediation guidance; deployment orchestration later. |

## Recommended Rollout Phases

1. **Control-plane foundation.** Enforce tenant-scoped auth/RBAC, subscription entitlements, module visibility, audit-backed impersonation, and `PolicyDocumentV2` schema.
2. **Policy editor and deployment.** Add module sections, inheritance, effective preview, Quick Deploy assignment, installer rollout status, and simulation gates.
3. **DLP, labels, and GenAI.** Implement sensitivity labels, GenAI/browser guardrails, clipboard/upload controls, label propagation, and redacted review summaries.
4. **Compliance expansion.** Add control reviews, attestation workflow, PDF export, framework-complete catalogues, and evidence object references.
5. **AI governance.** Centralize provider gateway, structured outputs, prompt/response hash audit, model allowlists, per-module budgets, and deterministic fallbacks.
6. **SIEM/HIDS v0.** Add log/FIM collectors, parser rules, MITRE mapping, software inventory, CVE/EPSS/KEV, retention/search, and active response gates.
7. **AV/EDR v0.** Add YARA/signature/IOC scanning, behaviour rules, anti-ransomware canaries, quarantine/isolate, and process tree telemetry.
8. **Firewall, web, and exploit hardening.** Add host firewall rules, URL/phishing reputation, network attack signatures, and exploit behaviour detections.
9. **External risk and intelligence.** Add DRP assets/findings, EASM discovery/exposure findings, threat intelligence validation, and takedown workflows.
10. **Incident graph and reporting.** Correlate all modules into incidents, add response approvals, executive reports, compliance evidence links, and white-label delivery.
11. **Deployment modes and operations.** Add on-prem relay, air-gap update path, object-store options, OpenTelemetry, backup/restore, retention policies, and cost telemetry.

## Acceptance Criteria for Default Policy v1.01

- The policy can be represented as one signed JSON document with separate module sections.
- The policy can be assigned to a customer during Quick Deploy and fetched by an enrolled agent.
- Unlicensed modules are visible as locked or omitted, never silently enabled.
- Every enabled module emits events with tenant context, policy version, module key, rule/detector id, action, and `evidence_controls`.
- Promotion to `block`, `isolate`, or `rollback` requires simulation output and an audit record.
- The console shows which GravityZone-style baseline features are delivered, planned, locked, or out of scope.
- Auditor export can prove the deterministic control path for DLP, policy changes, alerts, reviews, and response actions.
- Platform Owner, MSP Partner, Company Admin, Technician, and Viewer roles see only the policy sections and customers their scope allows.
- Subscription entitlements control module visibility, policy validation, agent activation, reporting, and usage limits.
- AI provider use is tenant-configured, quota-limited, redacted where required, and fully auditable by hash and source reference.
- DRP, EASM, endpoint, DLP, SIEM/HIDS, threat-intel, and response events can all join into one incident graph and one evidence export.
- Reports and compliance packs cite evidence refs rather than free-text claims.
- Cloud, MSP-hosted, customer-hosted, and air-gapped deployment profiles can all use the same policy envelope with different relay/update/storage settings.