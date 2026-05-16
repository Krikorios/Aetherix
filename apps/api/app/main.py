from fastapi import FastAPI

from app.schemas import DlpScanRequest, DlpScanResponse, Endpoint, Policy
from app.services.dlp import scan_text

app = FastAPI(title="Aetherix DLP API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/dlp/scan", response_model=DlpScanResponse)
def scan_dlp(request: DlpScanRequest) -> DlpScanResponse:
    return scan_text(request)


@app.get("/endpoints", response_model=list[Endpoint])
def endpoints() -> list[Endpoint]:
    return [
        Endpoint(id="mac-001", hostname="finance-macbook", os="macOS", status="healthy", risk_score=18),
        Endpoint(id="win-014", hostname="legal-workstation", os="Windows", status="attention", risk_score=72),
        Endpoint(id="linux-007", hostname="build-runner", os="Linux", status="healthy", risk_score=31),
    ]


@app.get("/policies/active", response_model=Policy)
def active_policy() -> Policy:
    return Policy(
        id="policy-default",
        name="Default GenAI DLP Guardrail",
        mode="monitor",
        protected_entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
    )
