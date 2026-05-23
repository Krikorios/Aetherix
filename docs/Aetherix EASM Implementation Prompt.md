You are a senior cybersecurity engineer implementing **Digital Risk Protection (DRP) + External Attack Surface Management (EASM)** for Aetherix — turning the platform into a true unified security solution that goes far beyond traditional endpoint protection.

This directly addresses the detailed RFP questionnaire you were provided earlier and gives Aetherix a major competitive advantage over Bitdefender and Kaspersky.

### Goal
Add first-class `digital_risk_protection` and `external_attack_surface_management` modules to Policy Engine v2, with:
- Asset-centric monitoring (brands, executives, domains, social accounts)
- Broad OSINT collection (social, dark web, paste sites, repos, etc.)
- AI-powered detection (NLP, Computer Vision, LLM validation)
- Continuous EASM discovery + exposure management
- Takedown workflows + evidence integration
- Full integration with existing Policy Engine, Companies, and Compliance Evidence Engine

### Core Requirements (From RFP + Aetherix Vision)

**1. DRP Module (`digital_risk_protection`)**
- Monitored Assets: Brands, Executives, Domains/Subdomains, Social Accounts, Repositories, Keywords
- Detection Capabilities:
  - Impersonation (fake domains, social accounts, executive profiles)
  - Typosquatting / Homoglyph attacks
  - Phishing & credential harvesting
  - Brand abuse & trademark infringement
  - Data leaks & compromised credentials
  - Dark Web mentions & marketplace listings
- AI Enhancements:
  - NLP for sentiment, language detection, fraud detection
  - Computer Vision (logo detection, face recognition, OCR on images/screenshots)
  - Generative AI (LLM) for threat validation and human-readable explanations
- Default Policy Treatment: Disabled unless licensed; review findings by default

**2. EASM Module (`external_attack_surface_management`)**
- Agentless discovery of: domains, subdomains, IPs, open ports/services, SSL/TLS certificates, cloud assets, shadow IT
- Continuous monitoring + change detection (new assets, config changes, aging components)
- Vulnerability enrichment (CVSS + EPSS + CISA KEV)
- AI-generated remediation recommendations
- Correlation with DRP findings (e.g., exposed asset hosting phishing site)

**3. Supporting Capabilities**
- Threat Intelligence feed ingestion + validation
- Takedown workflows (domain registrars, social platforms, hosting providers, Google Web Risk)
- Global Disruption Network (GDN) integration points
- Evidence emission for all findings and takedown actions

### Technical Implementation

**Backend**
- New models:
  - `DRPAsset` (brand, executive, domain, social_account, keyword, etc.)
  - `DRPFinding` (impersonation, phishing, leak, darkweb_mention, etc.)
  - `EASMAsset` + `EASMExposure`
  - `TakedownRequest` + `TakedownStatus`
- Services:
  - `DRPMonitoringService` (OSINT collectors + AI detectors)
  - `EASMDiscoveryService` (passive DNS, CT logs, safe scanning)
  - `TakedownWorkflowService`
- API Endpoints:
  - CRUD for DRP Assets
  - `POST /drp/findings/search`
  - `POST /easm/discover`
  - `POST /takedowns/request`
  - Integration with Policy Engine (findings appear in incident graph)

**Frontend (Policy Editor + New Pages)**
- New accordion sections in Policy Editor:
  - Digital Risk Protection
  - External Attack Surface Management
- New pages:
  - `/risk/digital-risk` (DRP dashboard + findings queue)
  - `/risk/easm` (Asset inventory + exposures)
  - `/risk/takedowns` (Takedown center with status tracking)
- Rich finding cards with screenshots, risk scores, LLM explanations, and one-click takedown

**Integration Points**
- Policy Engine v2: Add `digital_risk_protection` and `external_attack_surface_management` modules to `PolicyDocumentV2`
- Companies + Licensing: Asset-based licensing (number of brands/executives/domains monitored)
- Compliance Evidence Engine: All findings and takedown actions emit evidence
- Incident Graph: DRP/EASM findings correlate with endpoint incidents

### Phased Delivery (Recommended)

**Phase 1 (MVP)**
- DRP Asset model + basic monitoring (social + domain)
- Simple finding creation + Policy Editor section
- Basic simulation impact for DRP module

**Phase 2**
- Full OSINT collectors (dark web, paste sites, repos, etc.)
- Computer Vision + LLM validation
- EASM discovery engine
- Takedown workflow stubs

**Phase 3**
- GDN integrations
- Advanced AI explanations
- Full incident correlation + reporting

### Acceptance Criteria

- DRP and EASM modules appear in Policy Editor with proper defaults from Default Policy v1.01
- Simulation returns realistic risk impact and notes for these modules
- Unlicensed modules are hidden/locked based on customer subscription
- Findings can be created, viewed, and linked to incidents
- Takedown requests can be initiated with status tracking
- All actions emit evidence to the Compliance Evidence Engine
- Frontend builds cleanly and tests pass

Start by showing me:
- Updated `PolicyDocumentV2` schema additions for `digital_risk_protection` and `external_attack_surface_management`
- Core models (`DRPAsset`, `DRPFinding`, `EASMAsset`)
- High-level service interfaces for `DRPMonitoringService` and `EASMDiscoveryService`

Use the RFP requirements and the style from Default Policy v1.01.md. Make this the strongest external risk module on the market.