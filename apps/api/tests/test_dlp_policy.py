from app.schemas import DlpFinding, DlpScanResponse, Policy
from app.services.dlp import apply_policy


def test_block_policy_returns_block_for_protected_finding() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[
            DlpFinding(
                entity_type="EMAIL_ADDRESS",
                start=8,
                end=25,
                score=0.85,
                text="admin@example.com",
            )
        ],
    )
    policy = Policy(
        id="policy-test",
        name="Block PII",
        mode="block",
        protected_entities=["EMAIL_ADDRESS"],
    )

    decision = apply_policy(response, policy)

    assert decision.action == "block"
    assert [finding.entity_type for finding in decision.findings] == ["EMAIL_ADDRESS"]


def test_policy_filters_unprotected_findings() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[
            DlpFinding(
                entity_type="EMAIL_ADDRESS",
                start=8,
                end=25,
                score=0.85,
                text="admin@example.com",
            ),
            DlpFinding(
                entity_type="PHONE_NUMBER",
                start=35,
                end=47,
                score=0.7,
                text="212-555-0100",
            ),
        ],
    )
    policy = Policy(
        id="policy-test",
        name="Email Only",
        mode="review",
        protected_entities=["EMAIL_ADDRESS"],
    )

    decision = apply_policy(response, policy)

    assert decision.action == "review"
    assert [finding.entity_type for finding in decision.findings] == ["EMAIL_ADDRESS"]


def test_monitor_policy_allows_but_keeps_findings_for_alerting() -> None:
    response = DlpScanResponse(
        action="review",
        findings=[
            DlpFinding(
                entity_type="CREDIT_CARD",
                start=12,
                end=31,
                score=0.65,
                text="4111 1111 1111 1111",
            )
        ],
    )
    policy = Policy(
        id="policy-test",
        name="Monitor Cards",
        mode="monitor",
        protected_entities=["CREDIT_CARD"],
    )

    decision = apply_policy(response, policy)

    assert decision.action == "allow"
    assert [finding.entity_type for finding in decision.findings] == ["CREDIT_CARD"]