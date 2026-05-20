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
