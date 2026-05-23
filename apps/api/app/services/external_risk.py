"""High-level service interfaces for Digital Risk Protection and EASM.

These interfaces define the contract for external risk collection,
AI-assisted validation, and asset/exposure discovery workflows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.schemas import (
    DRPAsset,
    DRPFinding,
    DigitalRiskProtectionModule,
    EASMAsset,
    ExternalAttackSurfaceManagementModule,
)


class DRPCollectionSnapshot(dict):
    """Raw collector snapshot keyed by source (social, darkweb, repos, etc.)."""


class EASMExposureSnapshot(dict):
    """Raw exposure metadata keyed by exposure id or service fingerprint."""


class DRPMonitoringService(Protocol):
    """Contract for DRP asset monitoring and finding production."""

    def upsert_asset(self, asset: DRPAsset, *, actor: str) -> DRPAsset:
        """Create/update a monitored DRP asset."""

    def disable_asset(self, asset_id: UUID, *, actor: str) -> None:
        """Disable monitoring for a DRP asset without deleting history."""

    def collect_osint(
        self,
        *,
        customer_id: UUID,
        policy: DigitalRiskProtectionModule,
        since: datetime | None = None,
    ) -> DRPCollectionSnapshot:
        """Collect raw OSINT records across configured DRP sources."""

    def detect_findings(
        self,
        *,
        customer_id: UUID,
        policy: DigitalRiskProtectionModule,
        snapshot: DRPCollectionSnapshot,
    ) -> list[DRPFinding]:
        """Run impersonation/leak/phishing detectors and return normalized findings."""

    def validate_findings_with_ai(
        self,
        *,
        findings: list[DRPFinding],
        policy: DigitalRiskProtectionModule,
    ) -> list[DRPFinding]:
        """Apply NLP/CV/LLM validation to findings and enrich explanations."""

    def emit_finding_evidence(self, *, finding: DRPFinding, actor: str) -> None:
        """Emit compliance evidence for a DRP finding lifecycle action."""


class EASMDiscoveryService(Protocol):
    """Contract for external asset discovery and exposure monitoring."""

    def discover_assets(
        self,
        *,
        customer_id: UUID,
        policy: ExternalAttackSurfaceManagementModule,
    ) -> list[EASMAsset]:
        """Discover internet-facing assets (agentless)."""

    def detect_changes(
        self,
        *,
        customer_id: UUID,
        policy: ExternalAttackSurfaceManagementModule,
    ) -> list[EASMAsset]:
        """Detect newly observed assets and material configuration changes."""

    def enrich_exposures(
        self,
        *,
        customer_id: UUID,
        assets: list[EASMAsset],
        policy: ExternalAttackSurfaceManagementModule,
    ) -> EASMExposureSnapshot:
        """Enrich discovered assets with CVSS/EPSS/CISA KEV intelligence."""

    def correlate_with_drp(
        self,
        *,
        customer_id: UUID,
        assets: list[EASMAsset],
        drp_findings: list[DRPFinding],
    ) -> EASMExposureSnapshot:
        """Link EASM assets/exposures to DRP findings for unified incidents."""

    def emit_discovery_evidence(
        self,
        *,
        customer_id: UUID,
        actor: str,
        payload: EASMExposureSnapshot,
    ) -> None:
        """Emit compliance evidence for discovery/exposure lifecycle actions."""
