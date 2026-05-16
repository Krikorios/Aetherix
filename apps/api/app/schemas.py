from pydantic import BaseModel, Field


class DlpScanRequest(BaseModel):
    text: str = Field(min_length=1)
    language: str = "en"


class DlpFinding(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    text: str


class DlpScanResponse(BaseModel):
    findings: list[DlpFinding]
    action: str


class Endpoint(BaseModel):
    id: str
    hostname: str
    os: str
    status: str
    risk_score: int


class Policy(BaseModel):
    id: str
    name: str
    mode: str
    protected_entities: list[str]


class Alert(BaseModel):
    id: str
    title: str
    severity: str
    endpoint_id: str
    recommended_action: str
