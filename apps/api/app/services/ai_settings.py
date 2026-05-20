"""Per-company AI provider settings.

Stores which LLM provider / model a given customer wants Aetherix to consult
when enriching DLP semantic assessments (and, eventually, alert summaries).
API keys are encrypted at rest with Fernet using ``AETHERIX_AI_SECRET_KEY``.

Subscription gating
-------------------
A subscription's ``core_features`` JSON array may include one of:

* ``"ai_tier:none"``     — AI must stay disabled.
* ``"ai_tier:hosted"``   — only the ``aetherix-hosted`` (or ``disabled``)
                           provider is allowed; no BYO keys.
* ``"ai_tier:byo"``      — any provider is allowed.

When the feature flag is absent the default is ``hosted`` (safe).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken

from app.db import connection
from app.schemas import (
    AiProvider,
    CustomerAiSettings,
    CustomerAiSettingsUpdate,
)

LOGGER = logging.getLogger(__name__)


class AiSettingsError(Exception):
    """Domain error for AI settings operations (maps to 4xx)."""


# ---------------------------------------------------------------------------
# Fernet helpers
# ---------------------------------------------------------------------------


_DEV_KEY_WARNING_EMITTED = False


def _fernet() -> Fernet:
    """Return the process Fernet instance.

    In production ``AETHERIX_AI_SECRET_KEY`` MUST be set to a url-safe base64
    32-byte key (``Fernet.generate_key()``). For local dev / tests we fall
    back to a deterministic key derived from ``AETHERIX_DEV_AI_KEY`` (or a
    stable default) and emit a one-time warning. The dev key never decrypts
    production ciphertexts because they were encrypted with a different key.
    """

    global _DEV_KEY_WARNING_EMITTED
    raw = os.getenv("AETHERIX_AI_SECRET_KEY")
    if raw:
        try:
            return Fernet(raw.encode("utf-8") if isinstance(raw, str) else raw)
        except ValueError as error:
            raise AiSettingsError(
                "AETHERIX_AI_SECRET_KEY is not a valid Fernet key (use Fernet.generate_key())"
            ) from error
    # Dev/test fallback. Deterministic so re-starts can still decrypt.
    dev_seed = os.getenv("AETHERIX_DEV_AI_KEY", "aetherix-dev-ai-key-change-me-please!!")
    import base64
    import hashlib

    digest = hashlib.sha256(dev_seed.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    if not _DEV_KEY_WARNING_EMITTED:
        LOGGER.warning(
            "AETHERIX_AI_SECRET_KEY not set; using derived dev key. "
            "Do not use this in production."
        )
        _DEV_KEY_WARNING_EMITTED = True
    return Fernet(key)


def _encrypt(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode("utf-8"))


def _decrypt(ciphertext: bytes) -> str:
    try:
        return _fernet().decrypt(bytes(ciphertext)).decode("utf-8")
    except InvalidToken as error:
        raise AiSettingsError(
            "stored AI credential could not be decrypted with the current key"
        ) from error


# ---------------------------------------------------------------------------
# Provider catalog
# ---------------------------------------------------------------------------


def _row_to_provider(row: dict) -> AiProvider:
    return AiProvider(
        slug=row["slug"],
        display_name=row["display_name"],
        kind=row["kind"],
        requires_byo_key=row["requires_byo_key"],
        default_endpoint=row["default_endpoint"],
        supported_models=row["supported_models"] or [],
        notes=row["notes"],
    )


def list_providers() -> list[AiProvider]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from ai_providers order by slug")
        return [_row_to_provider(row) for row in cur.fetchall()]


def get_provider(slug: str) -> AiProvider | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from ai_providers where slug = %s", (slug,))
        row = cur.fetchone()
    return _row_to_provider(row) if row else None


# ---------------------------------------------------------------------------
# Per-customer settings
# ---------------------------------------------------------------------------


def _row_to_settings(row: dict) -> CustomerAiSettings:
    return CustomerAiSettings(
        customer_id=row["customer_id"],
        provider_slug=row["provider_slug"],
        model=row["model"],
        endpoint=row["endpoint"],
        api_key_last4=row["api_key_last4"],
        has_api_key=row["api_key_ciphertext"] is not None,
        data_residency=row["data_residency"],
        redact_pii_before_send=row["redact_pii_before_send"],
        enabled=row["enabled"],
        max_calls_per_day=row["max_calls_per_day"],
        updated_at=row["updated_at"],
        updated_by=row["updated_by"],
    )


def get_settings(customer_id: UUID) -> CustomerAiSettings | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from customer_ai_settings where customer_id = %s",
            (str(customer_id),),
        )
        row = cur.fetchone()
    return _row_to_settings(row) if row else None


# Subscription gating -------------------------------------------------------


def _ai_tier_for_customer(customer_id: UUID) -> str:
    """Return ``none`` / ``hosted`` / ``byo`` based on the active license.

    Reads ``core_features`` from the company's subscription. Defaults to
    ``hosted`` when no license is present (e.g. trial / dev) — callers
    still gate ``enabled`` so the actual outbound call only happens when
    a settings row exists.
    """

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select s.core_features
            from company_licenses cl
            join subscriptions s on s.id = cl.subscription_id
            where cl.customer_id = %s and cl.status = 'active'
            order by cl.issued_at desc
            limit 1
            """,
            (str(customer_id),),
        )
        row = cur.fetchone()
    if row is None:
        return "hosted"
    features = row["core_features"] or []
    for feature in features:
        if isinstance(feature, str) and feature.startswith("ai_tier:"):
            tier = feature.split(":", 1)[1].strip().lower()
            if tier in {"none", "hosted", "byo"}:
                return tier
    return "hosted"


def _validate_against_tier(
    payload: CustomerAiSettingsUpdate, provider: AiProvider, tier: str
) -> None:
    if tier == "none" and payload.enabled and provider.slug != "disabled":
        raise AiSettingsError(
            "current subscription does not include AI features"
        )
    if tier == "hosted" and provider.requires_byo_key and payload.enabled:
        raise AiSettingsError(
            f"provider {provider.slug!r} requires BYO key, "
            "but the current subscription only allows hosted AI"
        )
    if provider.requires_byo_key and payload.enabled:
        # Must have a key on file OR a key supplied now.
        # (Checked again by the upsert when api_key/clear_api_key are processed.)
        pass


def upsert_settings(
    customer_id: UUID,
    payload: CustomerAiSettingsUpdate,
    *,
    actor_id: UUID | None,
) -> CustomerAiSettings:
    provider = get_provider(payload.provider_slug)
    if provider is None:
        raise AiSettingsError(f"unknown AI provider {payload.provider_slug!r}")
    if payload.model not in provider.supported_models:
        raise AiSettingsError(
            f"model {payload.model!r} is not supported by {provider.slug!r}"
        )
    tier = _ai_tier_for_customer(customer_id)
    _validate_against_tier(payload, provider, tier)

    existing = get_settings(customer_id)

    # Resolve api_key state.
    if payload.clear_api_key:
        new_ciphertext: bytes | None = None
        new_last4: str | None = None
    elif payload.api_key:
        new_ciphertext = _encrypt(payload.api_key)
        new_last4 = payload.api_key[-4:] if len(payload.api_key) >= 4 else "****"
    else:
        # Keep the existing key (if any) untouched.
        new_ciphertext = _load_ciphertext(customer_id) if existing else None
        new_last4 = existing.api_key_last4 if existing else None

    if provider.requires_byo_key and payload.enabled and new_ciphertext is None:
        raise AiSettingsError(
            f"provider {provider.slug!r} requires an API key before it can be enabled"
        )

    endpoint = payload.endpoint or provider.default_endpoint
    now = datetime.now(UTC)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customer_ai_settings (
                customer_id, provider_slug, model, endpoint,
                api_key_ciphertext, api_key_last4,
                data_residency, redact_pii_before_send,
                enabled, max_calls_per_day,
                updated_at, updated_by
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (customer_id) do update
                set provider_slug = excluded.provider_slug,
                    model = excluded.model,
                    endpoint = excluded.endpoint,
                    api_key_ciphertext = excluded.api_key_ciphertext,
                    api_key_last4 = excluded.api_key_last4,
                    data_residency = excluded.data_residency,
                    redact_pii_before_send = excluded.redact_pii_before_send,
                    enabled = excluded.enabled,
                    max_calls_per_day = excluded.max_calls_per_day,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
            returning *
            """,
            (
                str(customer_id),
                provider.slug,
                payload.model,
                endpoint,
                new_ciphertext,
                new_last4,
                payload.data_residency,
                payload.redact_pii_before_send,
                payload.enabled,
                payload.max_calls_per_day,
                now,
                str(actor_id) if actor_id else None,
            ),
        )
        row = cur.fetchone()
    return _row_to_settings(row)


def delete_settings(customer_id: UUID) -> bool:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "delete from customer_ai_settings where customer_id = %s",
            (str(customer_id),),
        )
        return cur.rowcount > 0


def _load_ciphertext(customer_id: UUID) -> bytes | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select api_key_ciphertext from customer_ai_settings where customer_id = %s",
            (str(customer_id),),
        )
        row = cur.fetchone()
    if row is None or row["api_key_ciphertext"] is None:
        return None
    return bytes(row["api_key_ciphertext"])


# ---------------------------------------------------------------------------
# Resolver for the semantic LLM hook
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedAiConfig:
    """Effective per-call AI configuration."""

    provider_slug: str
    model: str
    endpoint: str | None
    api_key: str | None
    redact_pii_before_send: bool


def resolve_for_customer(customer_id: UUID | None) -> ResolvedAiConfig | None:
    """Resolve effective AI config for an outbound LLM call.

    Returns ``None`` when the caller should fall back to the deterministic
    rule-based path (the historical behavior). Disabled or unconfigured
    customers also return ``None``.
    """

    if customer_id is None:
        return None
    settings = get_settings(customer_id)
    if settings is None or not settings.enabled:
        return None
    if settings.provider_slug == "disabled":
        return None
    provider = get_provider(settings.provider_slug)
    if provider is None:
        LOGGER.warning(
            "customer %s references unknown provider %s",
            customer_id,
            settings.provider_slug,
        )
        return None
    api_key: str | None = None
    if provider.requires_byo_key:
        ciphertext = _load_ciphertext(customer_id)
        if ciphertext is None:
            LOGGER.warning(
                "customer %s has provider %s enabled without an API key on file",
                customer_id,
                provider.slug,
            )
            return None
        try:
            api_key = _decrypt(ciphertext)
        except AiSettingsError as error:
            LOGGER.warning("decrypt failed for customer %s: %s", customer_id, error)
            return None
    return ResolvedAiConfig(
        provider_slug=provider.slug,
        model=settings.model,
        endpoint=settings.endpoint or provider.default_endpoint,
        api_key=api_key,
        redact_pii_before_send=settings.redact_pii_before_send,
    )


# ---------------------------------------------------------------------------
# Daily call quota
# ---------------------------------------------------------------------------


def check_and_consume_quota(customer_id: UUID, max_calls_per_day: int) -> bool:
    """Atomically increment today's call count for ``customer_id``.

    Returns ``True`` when the call should proceed (post-increment count is
    within the limit) and ``False`` when the customer is over budget; in the
    latter case the row is rolled back to the previous value so that future
    days are not pre-charged.
    """

    if max_calls_per_day <= 0:
        return False
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customer_ai_usage_daily (customer_id, day, calls, last_called_at)
            values (%s, current_date, 1, %s)
            on conflict (customer_id, day)
            do update set calls = customer_ai_usage_daily.calls + 1,
                          last_called_at = excluded.last_called_at
            returning calls
            """,
            (str(customer_id), now),
        )
        row = cur.fetchone()
        calls = int(row["calls"])
        if calls > max_calls_per_day:
            cur.execute(
                "update customer_ai_usage_daily set calls = calls - 1 "
                "where customer_id = %s and day = current_date",
                (str(customer_id),),
            )
            return False
    return True


def get_usage_today(customer_id: UUID) -> int:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select calls from customer_ai_usage_daily "
            "where customer_id = %s and day = current_date",
            (str(customer_id),),
        )
        row = cur.fetchone()
    return int(row["calls"]) if row else 0


# ---------------------------------------------------------------------------
# Live provider probe (POST /companies/{id}/ai/test)
# ---------------------------------------------------------------------------


def _http_probe(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 5.0,
) -> tuple[int, str]:
    """Tiny urllib wrapper -- monkeypatched in tests."""

    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read(2048).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, str(error)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return 0, f"{type(error).__name__}: {error}"


def test_settings(customer_id: UUID):
    """Run a minimal live probe against the customer's configured provider.

    Returns an :class:`AiProbeResult` describing whether the credentials and
    endpoint accept a trivial request. Never raises.
    """

    from app.schemas import AiProbeResult

    settings = get_settings(customer_id)
    if settings is None:
        return AiProbeResult(ok=False, message="AI settings are not configured for this company.")
    if not settings.enabled:
        return AiProbeResult(
            ok=False,
            provider_slug=settings.provider_slug,
            model=settings.model,
            message="AI is disabled for this company; enable it before testing.",
        )
    if settings.provider_slug == "disabled":
        return AiProbeResult(
            ok=False,
            provider_slug="disabled",
            message="Provider is set to 'disabled'.",
        )
    provider = get_provider(settings.provider_slug)
    if provider is None:
        return AiProbeResult(
            ok=False,
            provider_slug=settings.provider_slug,
            message=f"Unknown provider '{settings.provider_slug}'.",
        )

    endpoint = settings.endpoint or provider.default_endpoint
    api_key: str | None = None
    if provider.requires_byo_key:
        ciphertext = _load_ciphertext(customer_id)
        if ciphertext is None:
            return AiProbeResult(
                ok=False,
                provider_slug=provider.slug,
                model=settings.model,
                message="Provider requires an API key but none is stored.",
            )
        try:
            api_key = _decrypt(ciphertext)
        except AiSettingsError as error:
            return AiProbeResult(
                ok=False,
                provider_slug=provider.slug,
                model=settings.model,
                message=f"Stored credential could not be decrypted: {error}",
            )

    if not endpoint:
        # Hosted providers without an endpoint are healthy by configuration.
        return AiProbeResult(
            ok=True,
            provider_slug=provider.slug,
            model=settings.model,
            message="Hosted provider; no endpoint to probe.",
        )

    method, url, headers, body = _build_probe_request(provider.slug, endpoint, api_key, settings.model)
    started = datetime.now(UTC)
    status, snippet = _http_probe(method, url, headers=headers, body=body, timeout=5.0)
    latency_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

    if 200 <= status < 400:
        return AiProbeResult(
            ok=True,
            provider_slug=provider.slug,
            model=settings.model,
            latency_ms=latency_ms,
            status_code=status,
            message="Provider responded successfully.",
        )
    if status == 0:
        return AiProbeResult(
            ok=False,
            provider_slug=provider.slug,
            model=settings.model,
            latency_ms=latency_ms,
            message=f"Could not reach provider: {snippet[:200]}",
        )
    return AiProbeResult(
        ok=False,
        provider_slug=provider.slug,
        model=settings.model,
        latency_ms=latency_ms,
        status_code=status,
        message=f"Provider returned HTTP {status}: {snippet[:200]}",
    )


def _build_probe_request(
    slug: str,
    endpoint: str,
    api_key: str | None,
    model: str,
) -> tuple[str, str, dict[str, str], bytes | None]:
    """Return (method, url, headers, body) for a minimal liveness probe."""

    base = endpoint.rstrip("/")
    if slug == "openai":
        return "GET", f"{base}/models", {"Authorization": f"Bearer {api_key or ''}"}, None
    if slug == "anthropic":
        return (
            "GET",
            f"{base}/v1/models",
            {
                "x-api-key": api_key or "",
                "anthropic-version": "2023-06-01",
            },
            None,
        )
    if slug == "azure-openai":
        # Azure OpenAI: list deployments under the resource.
        return (
            "GET",
            f"{base}/openai/deployments?api-version=2024-08-01-preview",
            {"api-key": api_key or ""},
            None,
        )
    if slug == "ollama":
        return "GET", f"{base}/api/tags", {}, None
    # Generic OpenAI-compatible default (e.g. aetherix-hosted).
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    return "GET", f"{base}/models", headers, None


# ---------------------------------------------------------------------------
# Alert summary writer
# ---------------------------------------------------------------------------


def summarize_alert(customer_id: UUID, alert: dict) -> str | None:
    """Return a short AI-written summary for ``alert`` or ``None``.

    Falls back to ``None`` whenever AI is unavailable, disabled, over quota,
    or the upstream call fails -- callers should treat ``None`` as "leave
    ``ai_summary`` NULL".
    """

    config = resolve_for_customer(customer_id)
    if config is None:
        return None
    settings = get_settings(customer_id)
    if settings is None:
        return None
    if not check_and_consume_quota(customer_id, settings.max_calls_per_day):
        LOGGER.info("AI summary skipped for customer %s: daily quota exhausted", customer_id)
        return None

    payload = {
        "kind": "alert_summary",
        "provider": config.provider_slug,
        "model": config.model,
        "alert": {
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "confidence": alert.get("confidence"),
            "recommended_action": alert.get("recommended_action"),
            "payload": alert.get("payload"),
        },
    }
    import json as _json

    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    if not config.endpoint:
        return None
    status, body = _http_probe(
        "POST",
        config.endpoint,
        headers=headers,
        body=_json.dumps(payload).encode("utf-8"),
        timeout=5.0,
    )
    if not (200 <= status < 300):
        LOGGER.info("AI summary upstream returned status %s for customer %s", status, customer_id)
        return None
    try:
        data = _json.loads(body)
    except ValueError:
        return None
    text = data.get("summary") if isinstance(data, dict) else None
    if not isinstance(text, str) or not text.strip():
        return None
    return text.strip()[:2000]
