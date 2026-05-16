from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import Alert, DlpScanRequest, DlpScanResponse, Endpoint, Policy
from app.services.dlp import scan_text

app = FastAPI(title="Aetherix DLP API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/alerts", response_model=list[Alert])
def alerts() -> list[Alert]:
    return [
        Alert(
            id="alert-001",
            title="Possible customer PII pasted into browser AI session",
            severity="high",
            endpoint_id="win-014",
            recommended_action="Review and redact before allowing upload",
        ),
        Alert(
            id="alert-002",
            title="Legal workstation missing critical browser patch",
            severity="medium",
            endpoint_id="win-014",
            recommended_action="Schedule patch deployment during next maintenance window",
        ),
        Alert(
            id="alert-003",
            title="USB write policy changed to monitor mode",
            severity="low",
            endpoint_id="mac-001",
            recommended_action="Confirm exception owner and expiration date",
        ),
    ]
