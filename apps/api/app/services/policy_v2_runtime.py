"""Production runtime services for Policy Engine v2.

This module keeps validation, simulation, effective-policy resolution, and
structured evidence emission separate from route handlers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.db import connection
from app.schemas import (
    EvidenceEvent,
    PolicyDocumentV2Input,
    PolicyLineageV2,
    PolicySimulationModuleOutcome,
    PolicySimulationSummaryV2,
)
from app.services.compliance import controls_for_event
from app.services.crypto import canonical_json


DESTRUCTIVE_ACTIONS = {"block", "isolate", "rollback", "quarantine", "kill"}
REVIEW_ACTIONS = {"review", "operator_required", "monitor"}
ALLOWED_POLICY_ACTIONS = {"allow", "review", "block"}
DEFAULT_SENSITIVITY_LABELS = ["Public", "Internal", "Confidential", "Restricted"]
DEFAULT_GENAI_DESTINATIONS = ["copilot", "claude", "gemini", "chatgpt", "custom"]


class PolicyValidationService:
    """Validates policy structure and license-based module entitlements."""

    @staticmethod
    def validate_required_modules(
        payload: PolicyDocumentV2Input,
        required_module_keys: tuple[str, ...],
    ) -> None:
        missing = [key for key in required_module_keys if key not in payload.modules]
        if missing:
            raise ValueError(f"missing required modules: {', '.join(missing)}")

    @staticmethod
    def validate_entitlements(
        payload: PolicyDocumentV2Input,
        entitled_modules: set[str],
        core_modules: set[str],
    ) -> list[str]:
        locked: list[str] = []
        for key, module_payload in payload.modules.items():
            enabled = bool((module_payload or {}).get("enabled", True))
            if not enabled:
                continue
            if key in core_modules or key in entitled_modules:
                continue
            locked.append(key)
        return sorted(set(locked))

    @staticmethod
    def normalize_semantic_modules(modules: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        def _csv_list(value: Any, fallback: list[str]) -> list[str]:
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
            if isinstance(value, str):
                return [item.strip() for item in value.split(",") if item.strip()]
            return list(fallback)

        semantic_raw = dict(modules.get("semantic_dlp") or {})
        detectors = dict(semantic_raw.get("detectors") or {})
        actions = dict(semantic_raw.get("actions") or {})
        sensitivity_labels = _csv_list(
            semantic_raw.get("sensitivity_labels_csv") or semantic_raw.get("sensitivity_labels"),
            DEFAULT_SENSITIVITY_LABELS,
        )
        genai_destinations = _csv_list(
            semantic_raw.get("genai_destinations_csv") or semantic_raw.get("genai_destinations"),
            DEFAULT_GENAI_DESTINATIONS,
        )
        modules["semantic_dlp"] = {
            "enabled": bool(semantic_raw.get("enabled", False)),
            "sensitivity_labels": sensitivity_labels,
            "genai_destinations": genai_destinations,
            "sensitivity_labels_csv": ", ".join(sensitivity_labels),
            "genai_destinations_csv": ", ".join(genai_destinations),
            "actions": {
                "paste_sensitive": str(actions.get("paste_sensitive", semantic_raw.get("paste_sensitive_action", "review"))),
                "upload_restricted": str(
                    actions.get("upload_restricted", semantic_raw.get("upload_restricted_action", "block"))
                ),
                "copy_to_genai": str(actions.get("copy_to_genai", semantic_raw.get("copy_to_genai_action", "review"))),
            },
            "paste_sensitive_action": str(actions.get("paste_sensitive", semantic_raw.get("paste_sensitive_action", "review"))),
            "upload_restricted_action": str(
                actions.get("upload_restricted", semantic_raw.get("upload_restricted_action", "block"))
            ),
            "copy_to_genai_action": str(actions.get("copy_to_genai", semantic_raw.get("copy_to_genai_action", "review"))),
            "detectors": {
                "presidio": bool(detectors.get("presidio", semantic_raw.get("presidio_detector", True))),
                "llm_semantic": bool(detectors.get("llm_semantic", semantic_raw.get("llm_semantic_detector", True))),
                "custom_classifiers": _csv_list(
                    semantic_raw.get("custom_classifiers_csv") or detectors.get("custom_classifiers"),
                    [],
                ),
            },
            "presidio_detector": bool(detectors.get("presidio", semantic_raw.get("presidio_detector", True))),
            "llm_semantic_detector": bool(detectors.get("llm_semantic", semantic_raw.get("llm_semantic_detector", True))),
            "custom_classifiers_csv": ", ".join(
                _csv_list(
                    semantic_raw.get("custom_classifiers_csv") or detectors.get("custom_classifiers"),
                    [],
                )
            ),
        }

        guardrails_raw = dict(modules.get("genai_guardrails") or {})
        guardrail_actions = dict(guardrails_raw.get("actions") or {})
        guardrail_destinations = _csv_list(
            guardrails_raw.get("destinations_csv") or guardrails_raw.get("destinations"),
            modules["semantic_dlp"]["genai_destinations"],
        )
        paste_sensitive = guardrail_actions.get("paste_sensitive")
        if paste_sensitive is None:
            paste_sensitive = guardrails_raw.get("paste_sensitive_action")
        if paste_sensitive is None:
            paste_sensitive = modules["semantic_dlp"]["actions"]["paste_sensitive"]

        upload_restricted = guardrail_actions.get("upload_restricted")
        if upload_restricted is None:
            upload_restricted = guardrails_raw.get("upload_restricted_action")
        if upload_restricted is None:
            upload_restricted = modules["semantic_dlp"]["actions"]["upload_restricted"]

        copy_to_genai = guardrail_actions.get("copy_to_genai")
        if copy_to_genai is None:
            copy_to_genai = guardrails_raw.get("copy_to_genai_action")
        if copy_to_genai is None:
            copy_to_genai = modules["semantic_dlp"]["actions"]["copy_to_genai"]

        modules["genai_guardrails"] = {
            "enabled": bool(guardrails_raw.get("enabled", False)),
            "destinations": guardrail_destinations,
            "destinations_csv": ", ".join(guardrail_destinations),
            "browser_enforcement": bool(guardrails_raw.get("browser_enforcement", True)),
            "endpoint_enforcement": bool(guardrails_raw.get("endpoint_enforcement", True)),
            "actions": {
                "paste_sensitive": str(paste_sensitive),
                "upload_restricted": str(upload_restricted),
                "copy_to_genai": str(copy_to_genai),
            },
            "paste_sensitive_action": str(paste_sensitive),
            "upload_restricted_action": str(upload_restricted),
            "copy_to_genai_action": str(copy_to_genai),
        }
        return modules

    @staticmethod
    def validate_semantic_modules(payload: PolicyDocumentV2Input) -> None:
        semantic = payload.modules.get("semantic_dlp") or {}
        guardrails = payload.modules.get("genai_guardrails") or {}

        labels = semantic.get("sensitivity_labels") or []
        if not isinstance(labels, list) or not all(isinstance(item, str) and item for item in labels):
            raise ValueError("semantic_dlp.sensitivity_labels must be a non-empty string array")

        destinations = semantic.get("genai_destinations") or []
        if not isinstance(destinations, list) or not all(isinstance(item, str) and item for item in destinations):
            raise ValueError("semantic_dlp.genai_destinations must be a non-empty string array")

        actions = semantic.get("actions") or {}
        for key in ("paste_sensitive", "upload_restricted", "copy_to_genai"):
            if actions.get(key) not in ALLOWED_POLICY_ACTIONS:
                raise ValueError(f"semantic_dlp.actions.{key} must be one of allow/review/block")

        detectors = semantic.get("detectors") or {}
        custom = detectors.get("custom_classifiers") or []
        if not isinstance(custom, list) or not all(isinstance(item, str) and item for item in custom):
            raise ValueError("semantic_dlp.detectors.custom_classifiers must be a string array")

        guardrail_actions = (guardrails.get("actions") or {})
        for key in ("paste_sensitive", "upload_restricted", "copy_to_genai"):
            value = guardrail_actions.get(key)
            if value is not None and value not in ALLOWED_POLICY_ACTIONS:
                raise ValueError(f"genai_guardrails.actions.{key} must be one of allow/review/block")


class PolicySimulationService:
    """Deterministic simulation over every enabled policy module."""

    MODULE_IMPACT_WEIGHTS: dict[str, int] = {
        "block": 12,
        "isolate": 24,
        "rollback": 18,
        "quarantine": 10,
        "kill": 14,
        "review": 4,
        "enabled": 1,
        "disabled": 0,
    }

    MODULE_EVIDENCE_TAGS: dict[str, list[str]] = {
        "antimalware": ["iso27001-2022:A.8.7", "soc2-2017:CC7.2"],
        "behavior_monitoring": ["iso27001-2022:A.8.16", "nist-csf-2.0:DE.CM"],
        "ransomware_mitigation": ["iso27001-2022:A.8.7", "soc2-2017:CC6.1"],
        "anti_exploit": ["iso27001-2022:A.8.7", "nist-csf-2.0:PR.PS"],
        "edr": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
        "firewall": ["iso27001-2022:A.8.20", "soc2-2017:CC6.6"],
        "network_protection": ["iso27001-2022:A.8.21", "soc2-2017:CC6.6"],
        "web_protection": ["iso27001-2022:A.8.23", "soc2-2017:CC6.7"],
        "device_control": ["iso27001-2022:A.8.7", "soc2-2017:CC6.1"],
        "semantic_dlp": ["iso27001-2022:A.5.12", "gdpr:Art. 32"],
        "genai_guardrails": ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
        "siem_hids": ["iso27001-2022:A.8.15", "soc2-2017:CC7.2"],
        "integrity_monitoring": ["iso27001-2022:A.8.32", "soc2-2017:CC7.1"],
        "vulnerability_inventory": ["iso27001-2022:A.8.8", "nist-csf-2.0:ID.RA"],
        "digital_risk_protection": ["iso27001-2022:A.5.7", "soc2-2017:CC3.2"],
        "external_attack_surface_management": ["iso27001-2022:A.8.16", "nist-csf-2.0:DE.CM"],
        "threat_intelligence": ["iso27001-2022:A.5.7", "nist-csf-2.0:ID.RA"],
        "incident_correlation": ["iso27001-2022:A.5.24", "soc2-2017:CC7.3"],
        "compliance_evidence": ["soc2-2017:CC7.2", "nist-csf-2.0:RS.AN"],
    }

    @classmethod
    def simulate(
        cls,
        payload: PolicyDocumentV2Input,
    ) -> tuple[PolicySimulationSummaryV2, list[PolicySimulationModuleOutcome]]:
        outcomes: list[PolicySimulationModuleOutcome] = []
        enabled_count = 0
        block_count = 0
        isolate_count = 0
        rollback_count = 0
        destructive_modules = 0
        risk_delta_total = 0

        for module_name, module_payload in payload.modules.items():
            enabled = bool((module_payload or {}).get("enabled", True))
            if enabled:
                enabled_count += 1

            destructive = cls._collect_actions(module_payload if enabled else {}, DESTRUCTIVE_ACTIONS)
            review_actions = cls._collect_actions(module_payload if enabled else {}, REVIEW_ACTIONS)

            if not enabled:
                outcome = "disabled"
                risk_delta = cls.MODULE_IMPACT_WEIGHTS["disabled"]
            elif destructive:
                outcome = "blocked"
                risk_delta = sum(cls.MODULE_IMPACT_WEIGHTS[action] for action in destructive)
            elif review_actions:
                outcome = "reviewed"
                risk_delta = cls.MODULE_IMPACT_WEIGHTS["review"]
            else:
                outcome = "enabled"
                risk_delta = cls.MODULE_IMPACT_WEIGHTS["enabled"]

            destructive_modules += 1 if destructive else 0
            block_count += 1 if "block" in destructive else 0
            isolate_count += 1 if "isolate" in destructive else 0
            rollback_count += 1 if "rollback" in destructive else 0
            risk_delta_total += risk_delta

            evidence_tags = sorted(
                set(cls.MODULE_EVIDENCE_TAGS.get(module_name, []))
                | set(controls_for_event("policy_v2.simulate"))
            )

            notes: list[str] = []
            if destructive:
                notes.append("high_impact_action_requires_approval")
            if review_actions and not destructive:
                notes.append("operator_review_recommended")

            if module_name == "semantic_dlp" and enabled:
                semantic_adjustment, semantic_notes = cls._semantic_dlp_impact(module_payload)
                risk_delta += semantic_adjustment
                risk_delta_total += semantic_adjustment
                notes.extend(semantic_notes)

            if module_name == "genai_guardrails" and enabled:
                guardrail_adjustment, guardrail_notes = cls._genai_guardrail_impact(module_payload)
                risk_delta += guardrail_adjustment
                risk_delta_total += guardrail_adjustment
                notes.extend(guardrail_notes)

            if module_name == "edr" and enabled:
                edr_adjustment, edr_notes = cls._edr_impact(module_payload)
                risk_delta += edr_adjustment
                risk_delta_total += edr_adjustment
                notes.extend(edr_notes)

            if module_name == "external_attack_surface_management" and enabled:
                easm_adjustment, easm_notes = cls._easm_impact(module_payload)
                risk_delta += easm_adjustment
                risk_delta_total += easm_adjustment
                notes.extend(easm_notes)

            if module_name == "digital_risk_protection" and enabled:
                drp_adjustment, drp_notes = cls._drp_impact(module_payload)
                risk_delta += drp_adjustment
                risk_delta_total += drp_adjustment
                notes.extend(drp_notes)

            outcomes.append(
                PolicySimulationModuleOutcome(
                    module=module_name,
                    enabled=enabled,
                    outcome=outcome,
                    risk_delta=risk_delta,
                    destructive_actions=destructive,
                    would_trigger_gate=bool(destructive),
                    evidence_tags=evidence_tags,
                    notes=notes,
                )
            )

        summary = PolicySimulationSummaryV2(
            modules_total=len(outcomes),
            modules_enabled=enabled_count,
            modules_with_destructive_actions=destructive_modules,
            would_block=block_count,
            would_isolate=isolate_count,
            would_rollback=rollback_count,
            risk_delta_total=risk_delta_total,
            approval_required=destructive_modules > 0,
        )
        return summary, outcomes

    @staticmethod
    def _collect_actions(module_payload: Any, candidate_actions: set[str]) -> list[str]:
        seen: set[str] = set()

        def _walk(value: Any) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    _walk(nested)
                return
            if isinstance(value, list):
                for item in value:
                    _walk(item)
                return
            if isinstance(value, str) and value in candidate_actions:
                seen.add(value)

        _walk(module_payload)
        return sorted(seen)

    @classmethod
    def _semantic_dlp_impact(cls, module_payload: Any) -> tuple[int, list[str]]:
        semantic = dict(module_payload or {})
        actions = dict(semantic.get("actions") or {})
        detectors = dict(semantic.get("detectors") or {})

        adjustment = 0
        notes: list[str] = []
        for action_key in ("paste_sensitive", "upload_restricted", "copy_to_genai"):
            value = actions.get(action_key)
            if value in cls.MODULE_IMPACT_WEIGHTS:
                adjustment += cls.MODULE_IMPACT_WEIGHTS[value]
                notes.append(f"semantic_action:{action_key}:{value}")

        if detectors.get("presidio"):
            adjustment += 2
            notes.append("detector:presidio")
        if detectors.get("llm_semantic"):
            adjustment += 3
            notes.append("detector:llm_semantic")
        custom = detectors.get("custom_classifiers") or []
        if isinstance(custom, list) and custom:
            adjustment += min(6, len(custom) * 2)
            notes.append(f"detector:custom_classifiers:{len(custom)}")

        labels = semantic.get("sensitivity_labels") or []
        if isinstance(labels, list) and "Restricted" in labels:
            adjustment += 4
            notes.append("label:restricted_present")

        destinations = semantic.get("genai_destinations") or []
        if isinstance(destinations, list) and destinations:
            adjustment += min(4, len(destinations))
            notes.append(f"genai_destinations:{len(destinations)}")

        return adjustment, notes

    @classmethod
    def _genai_guardrail_impact(cls, module_payload: Any) -> tuple[int, list[str]]:
        guardrails = dict(module_payload or {})
        actions = dict(guardrails.get("actions") or {})

        adjustment = 0
        notes: list[str] = []
        for action_key in ("paste_sensitive", "upload_restricted", "copy_to_genai"):
            value = actions.get(action_key)
            if value in cls.MODULE_IMPACT_WEIGHTS:
                adjustment += cls.MODULE_IMPACT_WEIGHTS[value]
                notes.append(f"guardrail_action:{action_key}:{value}")

        if bool(guardrails.get("browser_enforcement", False)):
            adjustment += 3
            notes.append("enforcement:browser")
        if bool(guardrails.get("endpoint_enforcement", False)):
            adjustment += 3
            notes.append("enforcement:endpoint")

        destinations = guardrails.get("destinations") or []
        if isinstance(destinations, list) and destinations:
            adjustment += min(5, len(destinations))
            notes.append(f"guarded_destinations:{len(destinations)}")

        return adjustment, notes

    # -- EDR / EASM / DRP module-specific impact -------------------------------
    #
    # These functions translate per-module policy configuration into a
    # deterministic risk delta and human-readable notes the simulator
    # surfaces back to the operator. They do not perform IO; they read
    # the module payload exactly as authored. Runtime services that
    # actually act on policy (state.py EDR ingest, drp_easm service)
    # consume the same module payload from the effective policy resolver.

    EDR_DETECTOR_KEYS: tuple[str, ...] = (
        "yara_scan",
        "ioc_match",
        "ransomware_canary",
        "process_tree",
        "suspicious_process_chain",
    )

    EDR_RESPONSE_KEYS: tuple[str, ...] = (
        "yara_match",
        "ioc_match",
        "ransomware_canary",
        "suspicious_process_chain",
    )

    @classmethod
    def _edr_impact(cls, module_payload: Any) -> tuple[int, list[str]]:
        edr = dict(module_payload or {})
        detectors = dict(edr.get("detectors") or {})
        responses = dict(edr.get("responses") or {})

        adjustment = 0
        notes: list[str] = []

        for key in cls.EDR_DETECTOR_KEYS:
            if bool(detectors.get(key, True)):
                adjustment += 2
                notes.append(f"detector:{key}")

        # Per-event-kind response actions configured by the operator.
        # Anything matching an ALLOWED_POLICY_ACTIONS or destructive
        # action carries weight; unknown values are ignored.
        for key in cls.EDR_RESPONSE_KEYS:
            value = responses.get(key)
            if isinstance(value, str) and value in cls.MODULE_IMPACT_WEIGHTS:
                adjustment += cls.MODULE_IMPACT_WEIGHTS[value]
                notes.append(f"response:{key}:{value}")

        if bool(edr.get("auto_isolate", False)):
            adjustment += cls.MODULE_IMPACT_WEIGHTS["isolate"]
            notes.append("response:auto_isolate")
        if bool(edr.get("auto_rollback", False)):
            adjustment += cls.MODULE_IMPACT_WEIGHTS["rollback"]
            notes.append("response:auto_rollback")

        approval = str(edr.get("destructive_action_approval", "operator_required"))
        if approval in ("operator_required", "review"):
            notes.append(f"approval:{approval}")

        return adjustment, notes

    @classmethod
    def _easm_impact(cls, module_payload: Any) -> tuple[int, list[str]]:
        easm = dict(module_payload or {})
        adjustment = 0
        notes: list[str] = []

        sources = easm.get("discovery_sources") or []
        if isinstance(sources, list) and sources:
            adjustment += min(7, len(sources))
            notes.append(f"discovery_sources:{len(sources)}")

        enrichment = easm.get("vulnerability_enrichment") or []
        if isinstance(enrichment, list):
            for tag in ("cvss", "epss", "cisa_kev"):
                if tag in enrichment:
                    adjustment += 2
                    notes.append(f"enrichment:{tag}")

        if bool(easm.get("continuous_monitoring_enabled", True)):
            adjustment += 3
            notes.append("continuous_monitoring")
        if bool(easm.get("change_detection_enabled", True)):
            adjustment += 2
            notes.append("change_detection")
        if bool(easm.get("correlate_with_drp", False)):
            adjustment += 2
            notes.append("correlate_with_drp")

        default_action = str(easm.get("default_action", "review"))
        if default_action in cls.MODULE_IMPACT_WEIGHTS:
            adjustment += cls.MODULE_IMPACT_WEIGHTS[default_action]
            notes.append(f"default_action:{default_action}")

        # Safe-port-scan ceiling is an operational guardrail; flag it
        # so operators can see at-a-glance what the simulation assumed.
        try:
            max_ports = int(easm.get("max_safe_ports_per_asset", 0) or 0)
        except (TypeError, ValueError):
            max_ports = 0
        if max_ports > 0:
            notes.append(f"max_safe_ports:{max_ports}")

        return adjustment, notes

    @classmethod
    def _drp_impact(cls, module_payload: Any) -> tuple[int, list[str]]:
        drp = dict(module_payload or {})
        adjustment = 0
        notes: list[str] = []

        detections = drp.get("detections_enabled") or []
        if isinstance(detections, list) and detections:
            adjustment += min(8, len(detections))
            notes.append(f"detections:{len(detections)}")

        sources = drp.get("collection_sources") or []
        if isinstance(sources, list) and sources:
            adjustment += min(5, len(sources))
            notes.append(f"collection_sources:{len(sources)}")

        if bool(drp.get("ai_llm_validation_enabled", False)):
            adjustment += 3
            notes.append("ai_validation")

        if bool(drp.get("auto_takedown_enabled", False)):
            adjustment += cls.MODULE_IMPACT_WEIGHTS["block"]
            notes.append("auto_takedown_enabled")

        default_action = str(drp.get("default_action", "review"))
        if default_action in cls.MODULE_IMPACT_WEIGHTS:
            adjustment += cls.MODULE_IMPACT_WEIGHTS[default_action]
            notes.append(f"default_action:{default_action}")

        try:
            threshold = int(drp.get("confidence_threshold", 0) or 0)
        except (TypeError, ValueError):
            threshold = 0
        if threshold:
            notes.append(f"confidence_threshold:{threshold}")

        return adjustment, notes


class EffectivePolicyResolver:
    """Resolves inheritance and precedence from tenant -> endpoint scope."""

    @staticmethod
    def deep_merge(base: Any, override: Any) -> Any:
        if isinstance(base, dict) and isinstance(override, dict):
            merged = dict(base)
            for key, value in override.items():
                merged[key] = EffectivePolicyResolver.deep_merge(merged.get(key), value)
            return merged
        if isinstance(base, list) and isinstance(override, list):
            return override
        return override if override is not None else base

    @classmethod
    def merge_payloads(
        cls,
        payloads: list[PolicyDocumentV2Input],
    ) -> PolicyDocumentV2Input | None:
        merged_payload: PolicyDocumentV2Input | None = None
        for payload in payloads:
            if merged_payload is None:
                merged_payload = payload
                continue
            merged_payload = PolicyDocumentV2Input(
                schema_version="2.0",
                name=payload.name,
                scope=payload.scope,
                lineage=payload.lineage,
                modules=cls.deep_merge(merged_payload.modules, payload.modules),
                white_label_names=cls.deep_merge(
                    merged_payload.white_label_names,
                    payload.white_label_names,
                ),
            )
        return merged_payload

    @classmethod
    def resolve_lineage(
        cls,
        payload: PolicyDocumentV2Input,
        parent_loader,
        seen: set[UUID] | None = None,
    ) -> PolicyDocumentV2Input:
        parent_id = payload.lineage.parent_policy_id
        if parent_id is None:
            return payload

        visited = seen or set()
        if parent_id in visited:
            raise ValueError("policy lineage cycle detected")
        visited.add(parent_id)

        parent_payload = parent_loader(parent_id)
        resolved_parent = cls.resolve_lineage(parent_payload, parent_loader, visited)
        if payload.lineage.inheritance_mode == "replace":
            return payload

        return PolicyDocumentV2Input(
            schema_version="2.0",
            name=payload.name,
            scope=payload.scope,
            lineage=PolicyLineageV2(
                parent_policy_id=payload.lineage.parent_policy_id,
                inheritance_mode=payload.lineage.inheritance_mode,
            ),
            modules=cls.deep_merge(resolved_parent.modules, payload.modules),
            white_label_names=cls.deep_merge(
                resolved_parent.white_label_names,
                payload.white_label_names,
            ),
        )


class EvidenceEmitter:
    """Structured evidence sink for policy lifecycle events."""

    @staticmethod
    def emit(
        *,
        action: str,
        resource: str,
        actor: str,
        scope: dict[str, Any],
        payload: dict[str, Any],
        evidence_controls: list[str] | None = None,
    ) -> EvidenceEvent:
        now = datetime.now(UTC)
        event_id = uuid.uuid4()
        controls = evidence_controls if evidence_controls is not None else controls_for_event(action)

        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into evidence_events (
                    id, action, resource, actor, scope, payload,
                    evidence_controls, created_at
                ) values (
                    %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                    %s::jsonb, %s
                )
                """,
                (
                    event_id,
                    action,
                    resource,
                    actor,
                    json.dumps(scope),
                    json.dumps(payload),
                    json.dumps(controls),
                    now,
                ),
            )

        return EvidenceEvent(
            id=event_id,
            action=action,
            resource=resource,
            actor=actor,
            scope=scope,
            payload=payload,
            evidence_controls=controls,
            created_at=now,
        )


def policy_payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
