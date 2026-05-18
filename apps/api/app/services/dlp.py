import os
import re
from dataclasses import dataclass
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine

from app.schemas import DlpFinding, DlpScanRequest, DlpScanResponse, Policy
from app.services.semantic import BAND_RANK, analyze_context


@dataclass(frozen=True)
class LocalRecognizer:
    entity_type: str
    pattern: re.Pattern[str]
    score: float


LOCAL_RECOGNIZERS = [
    LocalRecognizer("EMAIL_ADDRESS", re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), 0.85),
    LocalRecognizer("PHONE_NUMBER", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), 0.7),
    LocalRecognizer("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,16}\b"), 0.65),
]


@lru_cache(maxsize=1)
def analyzer() -> AnalyzerEngine:
    return AnalyzerEngine()


def scan_text(request: DlpScanRequest) -> DlpScanResponse:
    if os.getenv("AETHERIX_USE_PRESIDIO") == "true":
        results = analyzer().analyze(text=request.text, language=request.language)
        findings = [
            DlpFinding(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end,
                score=round(result.score, 3),
                text=request.text[result.start : result.end],
            )
            for result in results
        ]
    else:
        findings = [
            DlpFinding(
                entity_type=recognizer.entity_type,
                start=match.start(),
                end=match.end(),
                score=recognizer.score,
                text=match.group(0),
            )
            for recognizer in LOCAL_RECOGNIZERS
            for match in recognizer.pattern.finditer(request.text)
        ]

    assessment = analyze_context(
        text=request.text,
        source=request.source,
        finding_count=len(findings),
        distinct_entities=len({finding.entity_type for finding in findings}),
    )

    action = "review" if findings else "allow"
    return DlpScanResponse(
        findings=findings,
        action=action,
        risk_score=assessment.risk_score,
        risk_band=assessment.risk_band,
        context_signals=list(assessment.signals),
        rationale=assessment.rationale,
    )


def apply_policy(response: DlpScanResponse, policy: Policy) -> DlpScanResponse:
    protected_entities = set(policy.protected_entities)
    protected_findings = [finding for finding in response.findings if finding.entity_type in protected_entities]

    if not protected_findings:
        return response.model_copy(update={"findings": [], "action": "allow"})

    if policy.mode == "block":
        action = "block"
    elif policy.mode == "review":
        action = "review"
    else:
        action = "allow"

    if policy.mode != "block":
        rank = BAND_RANK.get(response.risk_band, 0)
        threshold = BAND_RANK.get(policy.escalate_at, BAND_RANK["high"])
        genai_trigger = policy.genai_guardrail and "genai_sink_detected" in response.context_signals

        if rank >= threshold or genai_trigger:
            action = "review" if policy.mode == "monitor" else "block"
            if rank >= BAND_RANK["critical"] or (genai_trigger and rank >= BAND_RANK["high"]):
                action = "block"

    return response.model_copy(update={"findings": protected_findings, "action": action})
