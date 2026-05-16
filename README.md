# Aetherix Endpoint Security POC

This repository starts the two-week proof of concept from the proposal: a minimal endpoint agent, a Presidio-backed DLP API, and a basic security console.

## Workspace

- `apps/api` - FastAPI service for DLP scanning, policies, and endpoint state.
- `apps/console` - React/Vite dashboard for the first operator workflows.
- `agent` - Rust endpoint agent skeleton for local telemetry and enforcement experiments.
- `docs` - Product and engineering notes derived from the proposal.

## Quick Start

```bash
npm install
npm run dev
```

In another terminal:

```bash
cd apps/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## First POC Goals

1. Accept text samples and detect PII with Presidio-compatible scan results.
2. Show endpoint health, alerts, and policy state in the console.
3. Keep the agent contract small enough to replace mock telemetry with OS-specific collectors later.
