from app.schemas import DlpFinding, DlpScanResponse, Policy
from app.services.dlp import apply_policy


def _email_finding() -> DlpFinding:
    return DlpFinding(
        entity_type="EMAIL_ADDRESS",
        start=0,
        end=17,
        score=0.85,
        text="admin@example.com",
    )


def test_genai_guardrail_escalates_monitor_to_review() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[_email_finding()],
        risk_score=43,
        risk_band="medium",
        context_signals=["genai_sink_detected"],
        rationale="destination matches a known generative AI tool",
    )
    policy = Policy(
        id="policy-test",
        name="Monitor with guardrail",
        mode="monitor",
        protected_entities=["EMAIL_ADDRESS"],
    )

    decision = apply_policy(response, policy)

    assert decision.action == "review"
    assert [finding.entity_type for finding in decision.findings] == ["EMAIL_ADDRESS"]


def test_genai_guardrail_blocks_when_risk_is_high() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[_email_finding()],
        risk_score=70,
        risk_band="high",
        context_signals=["genai_sink_detected", "confidentiality_marker"],
        rationale="destination matches a known generative AI tool; text contains confidentiality markers",
    )
    policy = Policy(
        id="policy-test",
        name="Review with guardrail",
        mode="review",
        protected_entities=["EMAIL_ADDRESS"],
    )

    decision = apply_policy(response, policy)

    assert decision.action == "block"


def test_critical_band_blocks_even_without_genai_signal() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[_email_finding()],
        risk_score=80,
        risk_band="critical",
        context_signals=["confidentiality_marker", "bulk_pii", "entity_diversity"],
        rationale="text contains confidentiality markers; 6 sensitive findings across 3 entity type(s)",
    )
    policy = Policy(
        id="policy-test",
        name="Monitor",
        mode="monitor",
        protected_entities=["EMAIL_ADDRESS"],
        genai_guardrail=False,
    )

    decision = apply_policy(response, policy)

    assert decision.action == "block"


def test_guardrail_can_be_disabled() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[_email_finding()],
        risk_score=43,
        risk_band="medium",
        context_signals=["genai_sink_detected"],
        rationale="destination matches a known generative AI tool",
    )
    policy = Policy(
        id="policy-test",
        name="Monitor without guardrail",
        mode="monitor",
        protected_entities=["EMAIL_ADDRESS"],
        genai_guardrail=False,
    )

    decision = apply_policy(response, policy)

    assert decision.action == "allow"
