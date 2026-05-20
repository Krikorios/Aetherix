"""Semantic context analysis for the DLP engine.

This layer turns raw regex/Presidio findings into a context-aware risk
assessment. It looks at the destination ("source") of the scan request and the
text itself for signals that indicate elevated exfiltration risk:

* Generative-AI destinations (ChatGPT, Claude, Gemini, Copilot, ...).
* Confidentiality markers ("confidential", "NDA", "do not share", ...).
* Exfiltration intent verbs ("paste", "upload", "share", "send to", ...).
* Volume / diversity of sensitive findings already produced by the regex or
  Presidio layer.

The output feeds policy decisions in :mod:`app.services.dlp` so a generic
``monitor`` policy can be escalated to ``review`` or ``block`` when the
context warrants it, without rewriting per-tenant rules.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

LOGGER = logging.getLogger(__name__)

RiskBand = Literal["low", "medium", "high", "critical"]

BAND_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


GENAI_SINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"chat\.?gpt", re.IGNORECASE),
    re.compile(r"openai\.com", re.IGNORECASE),
    re.compile(r"claude(?:\.ai)?", re.IGNORECASE),
    re.compile(r"anthropic\.com", re.IGNORECASE),
    re.compile(r"gemini(?:\.google\.com)?", re.IGNORECASE),
    re.compile(r"\bbard\b", re.IGNORECASE),
    re.compile(r"copilot(?:\.microsoft\.com)?", re.IGNORECASE),
    re.compile(r"m365\s*copilot", re.IGNORECASE),
    re.compile(r"perplexity(?:\.ai)?", re.IGNORECASE),
    re.compile(r"grok(?:\.com|\.x\.ai)?", re.IGNORECASE),
    re.compile(r"mistral(?:\.ai)?", re.IGNORECASE),
    re.compile(r"hugging\s*face", re.IGNORECASE),
)

CONFIDENTIALITY_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bconfidential\b", re.IGNORECASE),
    re.compile(r"internal[\s-]only", re.IGNORECASE),
    re.compile(r"do[\s-]not[\s-]share", re.IGNORECASE),
    re.compile(r"\bnda\b|non[\s-]disclosure", re.IGNORECASE),
    re.compile(r"\bproprietary\b", re.IGNORECASE),
    re.compile(r"trade\s+secret", re.IGNORECASE),
    re.compile(r"under\s+embargo", re.IGNORECASE),
    re.compile(r"attorney[\s-]client", re.IGNORECASE),
)

EXFIL_VERBS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:paste|pasting|pasted)\b", re.IGNORECASE),
    re.compile(r"\b(?:upload|uploading|uploaded)\b", re.IGNORECASE),
    re.compile(r"\bshare\s+(?:this|the|with|externally)\b", re.IGNORECASE),
    re.compile(r"\bsend\s+(?:this|the|to|over)\b", re.IGNORECASE),
    re.compile(r"\bexport(?:ing|ed)?\b", re.IGNORECASE),
    re.compile(r"\battach(?:ed|ing|ment)?\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class SemanticAssessment:
    """Aggregated semantic signals for one DLP scan."""

    risk_score: int
    risk_band: RiskBand
    signals: tuple[str, ...]
    rationale: str
    genai_sink: bool


def analyze_context(
    text: str,
    source: str | None,
    finding_count: int,
    distinct_entities: int,
    customer_id: UUID | None = None,
    findings: list | None = None,
) -> SemanticAssessment:
    """Produce a :class:`SemanticAssessment` for the given scan payload."""

    signals: list[str] = []
    score = 0
    haystack = f"{text}\n{source or ''}"

    genai_sink = any(pattern.search(haystack) for pattern in GENAI_SINK_PATTERNS)
    if genai_sink:
        signals.append("genai_sink_detected")
        score += 35

    if any(pattern.search(text) for pattern in CONFIDENTIALITY_MARKERS):
        signals.append("confidentiality_marker")
        score += 20

    if any(pattern.search(text) for pattern in EXFIL_VERBS):
        signals.append("exfil_intent")
        score += 15

    if finding_count >= 5:
        signals.append("bulk_pii")
        score += 20
    elif finding_count >= 2:
        signals.append("multiple_pii")
        score += 8

    if distinct_entities >= 3:
        signals.append("entity_diversity")
        score += 10

    score = min(100, score)
    band: RiskBand = (
        "critical"
        if score >= 75
        else "high"
        if score >= 50
        else "medium"
        if score >= 25
        else "low"
    )

    rationale_parts: list[str] = []
    if genai_sink:
        rationale_parts.append("destination matches a known generative AI tool")
    if "confidentiality_marker" in signals:
        rationale_parts.append("text contains confidentiality markers")
    if "exfil_intent" in signals:
        rationale_parts.append("text describes data movement actions")
    if finding_count >= 2:
        rationale_parts.append(
            f"{finding_count} sensitive findings across {distinct_entities} entity type(s)"
        )
    rationale = "; ".join(rationale_parts) or "no elevated semantic signals detected"

    llm_signals, llm_boost, llm_rationale = _consult_external_llm(
        text, source, signals, customer_id, findings
    )
    if llm_signals or llm_boost or llm_rationale:
        signals.extend(signal for signal in llm_signals if signal not in signals)
        score = min(100, score + max(0, llm_boost))
        band = (
            "critical"
            if score >= 75
            else "high"
            if score >= 50
            else "medium"
            if score >= 25
            else "low"
        )
        if llm_rationale:
            rationale = f"{rationale}; {llm_rationale}"

    return SemanticAssessment(
        risk_score=score,
        risk_band=band,
        signals=tuple(signals),
        rationale=rationale,
        genai_sink=genai_sink,
    )


def _consult_external_llm(
    text: str,
    source: str | None,
    signals: list[str],
    customer_id: UUID | None = None,
    findings: list | None = None,
) -> tuple[list[str], int, str]:
    """Optionally enrich the assessment with an external LLM classifier.

    Resolution order:

    1. **Per-tenant settings** — when ``customer_id`` is provided and the
       customer has enabled an AI provider via
       :mod:`app.services.ai_settings`, that configuration is used. The
       per-tenant ``max_calls_per_day`` quota and ``redact_pii_before_send``
       flag are enforced here.
    2. **Legacy env-var hook** — ``AETHERIX_SEMANTIC_LLM_URL`` (with optional
       ``AETHERIX_SEMANTIC_LLM_TOKEN`` / ``AETHERIX_SEMANTIC_LLM_TIMEOUT``).
       Preserved so existing single-tenant deployments keep working; defaults
       to redacting PII before send.

    The endpoint receives ``{text, source, signals, provider, model}`` as JSON
    and may return any subset of ``{additional_signals, risk_score_boost,
    rationale}``. Failures (network, timeout, malformed payload) are logged
    and swallowed so the deterministic rule-based assessment remains
    authoritative.
    """

    endpoint, token, provider_slug, model, redact = _resolve_llm_endpoint(customer_id)
    if not endpoint:
        return [], 0, ""

    # Per-tenant daily quota enforcement (skip for env fallback).
    if customer_id is not None and provider_slug != "env":
        try:
            from app.services.ai_settings import (
                check_and_consume_quota,
                get_settings,
            )

            settings = get_settings(customer_id)
            limit = settings.max_calls_per_day if settings else 0
            if not check_and_consume_quota(customer_id, limit):
                LOGGER.info(
                    "semantic LLM hook skipped for customer %s: daily quota exhausted",
                    customer_id,
                )
                return [], 0, ""
        except Exception as error:  # noqa: BLE001 - never break DLP on quota lookup
            LOGGER.warning("AI quota check failed: %s", error)
            return [], 0, ""

    payload_text = _redact_text(text, findings) if redact else text

    try:
        timeout = float(os.getenv("AETHERIX_SEMANTIC_LLM_TIMEOUT", "2.0"))
        body = json.dumps(
            {
                "text": payload_text,
                "source": source,
                "signals": signals,
                "provider": provider_slug,
                "model": model,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is operator-configured
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
        LOGGER.warning("semantic LLM hook failed: %s", error)
        return [], 0, ""

    additional = payload.get("additional_signals") or []
    boost = payload.get("risk_score_boost") or 0
    rationale = payload.get("rationale") or ""
    if not isinstance(additional, list):
        additional = []
    if not isinstance(boost, int):
        try:
            boost = int(boost)
        except (TypeError, ValueError):
            boost = 0
    if not isinstance(rationale, str):
        rationale = ""

    return [str(signal) for signal in additional], boost, rationale


def _resolve_llm_endpoint(
    customer_id: UUID | None,
) -> tuple[str | None, str | None, str | None, str | None, bool]:
    """Return (endpoint, bearer_token, provider_slug, model, redact_pii) for the call.

    Prefers per-tenant config; falls back to the env-var hook for back-compat.
    Returns ``(None, None, None, None, True)`` when no upstream is configured.
    """

    # Lazy import to avoid a cycle on module load.
    try:
        from app.services.ai_settings import resolve_for_customer
    except Exception:  # pragma: no cover - defensive
        resolve_for_customer = None  # type: ignore[assignment]

    if customer_id is not None and resolve_for_customer is not None:
        try:
            config = resolve_for_customer(customer_id)
        except Exception as error:  # noqa: BLE001 - never break DLP on AI lookup
            LOGGER.warning("AI settings lookup failed: %s", error)
            config = None
        if config is not None and config.endpoint:
            return (
                config.endpoint,
                config.api_key,
                config.provider_slug,
                config.model,
                bool(config.redact_pii_before_send),
            )

    endpoint = os.getenv("AETHERIX_SEMANTIC_LLM_URL")
    if endpoint:
        return endpoint, os.getenv("AETHERIX_SEMANTIC_LLM_TOKEN"), "env", None, True
    return None, None, None, None, True


def _redact_text(text: str, findings: list | None) -> str:
    """Replace DLP finding spans in ``text`` with ``[REDACTED:<entity>]``.

    Accepts a list of objects with ``start``, ``end`` and ``entity_type``
    attributes (pydantic ``DlpFinding`` instances) or dicts with the same
    keys. Spans are applied in descending order so earlier offsets are not
    invalidated by replacements.
    """

    if not findings:
        return text

    def _attr(item, key, default=None):
        if isinstance(item, dict):
            return item.get(key, default)
        return getattr(item, key, default)

    spans: list[tuple[int, int, str]] = []
    for finding in findings:
        start = _attr(finding, "start")
        end = _attr(finding, "end")
        entity = _attr(finding, "entity_type", "PII")
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        if start < 0 or end <= start or end > len(text):
            continue
        spans.append((start, end, str(entity)))

    if not spans:
        return text

    spans.sort(key=lambda s: s[0], reverse=True)
    redacted = text
    for start, end, entity in spans:
        redacted = redacted[:start] + f"[REDACTED:{entity}]" + redacted[end:]
    return redacted
