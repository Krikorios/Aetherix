# Proof-of-Concept Plan

## Proposal Review

The proposal is broad enough for a full enterprise endpoint platform, but the execution start should be deliberately narrow. The highest-risk assumptions are endpoint overhead, Presidio/semantic DLP quality, and whether the console can express useful policy decisions without becoming a full XDR product too early.

## Two-Week Slice

Week 1:

- Create monorepo, coding standards, and local development path.
- Build DLP API with a Presidio-backed scanner and deterministic fallback recognizers.
- Build dashboard views for endpoint inventory, alert triage, and policy editing.

Week 2:

- Add Rust agent telemetry contract and local mock collector.
- Wire console to API endpoints.
- Add sample policies and repeatable demo data.

## Acceptance Criteria

- A text sample containing email, phone, or credit-card-like content returns entity detections with confidence scores.
- Console renders endpoint health, high-risk alerts, and active policy state from API data.
- Agent can emit a signed JSON heartbeat payload locally.
