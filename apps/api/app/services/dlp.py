import os
import re
from dataclasses import dataclass
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine

from app.schemas import DlpFinding, DlpScanRequest, DlpScanResponse


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

    action = "review" if findings else "allow"
    return DlpScanResponse(findings=findings, action=action)
