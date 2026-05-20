from app.services import semantic
from app.services.semantic import analyze_context


def test_genai_destination_is_flagged() -> None:
    assessment = analyze_context(
        text="Please summarize this customer list.",
        source="browser paste -> chat.openai.com",
        finding_count=1,
        distinct_entities=1,
    )

    assert assessment.genai_sink is True
    assert "genai_sink_detected" in assessment.signals
    assert assessment.risk_band in {"medium", "high", "critical"}


def test_confidentiality_and_exfil_signals_compound() -> None:
    assessment = analyze_context(
        text="CONFIDENTIAL: do not share. Please upload this attached payroll export.",
        source="email outbound",
        finding_count=3,
        distinct_entities=2,
    )

    assert "confidentiality_marker" in assessment.signals
    assert "exfil_intent" in assessment.signals
    assert "multiple_pii" in assessment.signals
    assert assessment.risk_band in {"medium", "high", "critical"}
    assert assessment.risk_score >= 25


def test_low_risk_when_no_signals() -> None:
    assessment = analyze_context(
        text="Hello team, lunch at noon?",
        source=None,
        finding_count=0,
        distinct_entities=0,
    )

    assert assessment.genai_sink is False
    assert assessment.signals == ()
    assert assessment.risk_band == "low"
    assert assessment.risk_score == 0


def test_llm_hook_augments_assessment(monkeypatch) -> None:
    monkeypatch.setattr(
        semantic,
        "_consult_external_llm",
        lambda text, source, signals, customer_id=None: (["llm_intent_exfil"], 30, "LLM classified as exfiltration"),
    )

    assessment = analyze_context(
        text="Quarterly customer churn analysis attached.",
        source="slack outbound",
        finding_count=1,
        distinct_entities=1,
    )

    assert "llm_intent_exfil" in assessment.signals
    assert assessment.risk_score >= 30
    assert "LLM classified as exfiltration" in assessment.rationale


def test_llm_hook_failures_are_swallowed(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_SEMANTIC_LLM_URL", "http://127.0.0.1:1/unreachable")
    monkeypatch.setenv("AETHERIX_SEMANTIC_LLM_TIMEOUT", "0.05")

    assessment = analyze_context(text="hello", source=None, finding_count=0, distinct_entities=0)

    assert assessment.risk_band == "low"
    assert assessment.risk_score == 0
