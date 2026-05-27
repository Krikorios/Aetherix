from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from sqlalchemy import BigInteger, Date, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ComplianceAttestation(Base):
    __tablename__ = "compliance_attestations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    customer_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("customers.id", ondelete="CASCADE"))
    framework: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    attested_by_account_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("accounts.id", ondelete="SET NULL"))
    attested_role: Mapped[str] = mapped_column(Text, nullable=False)
    attested_name: Mapped[str] = mapped_column(Text, nullable=False)
    bundle_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signature_algo: Mapped[str] = mapped_column(Text, nullable=False, default="hmac-sha256")
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceReview(Base):
    __tablename__ = "compliance_reviews"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    customer_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("customers.id", ondelete="CASCADE"))
    source_table: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    framework: Mapped[str] = mapped_column(Text, nullable=False)
    control_id: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed_by_account_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("accounts.id", ondelete="SET NULL"))
    reviewed_by_role: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed_by_name: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceVaultReference(Base):
    __tablename__ = "compliance_vault_references"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    customer_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("customers.id", ondelete="CASCADE"))
    source_table: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    framework: Mapped[str] = mapped_column(Text, nullable=False)
    storage_kind: Mapped[str] = mapped_column(Text, nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)