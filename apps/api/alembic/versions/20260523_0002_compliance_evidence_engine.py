"""Add Compliance Evidence Engine schema

Revision ID: 20260523_0002
Revises: 20260519_0001
Create Date: 2026-05-23 08:15:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "20260523_0002"
down_revision = "20260519_0001"
branch_labels = None
depends_on = None


CONTROLS: tuple[tuple[str, str, str, str], ...] = (
    (
        "iso27001-2022",
        "A.5.12",
        "Classification of information",
        "Information is classified according to security needs and business value.",
    ),
    (
        "iso27001-2022",
        "A.8.10",
        "Information deletion",
        "Information stored in systems is deleted when no longer required.",
    ),
    (
        "iso27001-2022",
        "A.8.12",
        "Data leakage prevention",
        "Data leakage prevention measures are applied to systems and networks.",
    ),
    (
        "iso27001-2022",
        "A.8.16",
        "Monitoring activities",
        "Networks, systems, and applications are monitored for anomalous behaviour.",
    ),
    (
        "soc2-2017",
        "CC6.1",
        "Logical access controls",
        "Logical access security software and infrastructure restrict access to information assets.",
    ),
    (
        "soc2-2017",
        "CC7.2",
        "Security event monitoring",
        "Security events are monitored to detect anomalies and threats.",
    ),
    (
        "nist-csf-2.0",
        "DE.CM",
        "Continuous monitoring",
        "Assets are monitored to find anomalies, indicators of compromise, and adverse events.",
    ),
    (
        "nist-csf-2.0",
        "RS.AN",
        "Incident analysis",
        "Investigations are conducted to support effective response.",
    ),
    (
        "gdpr",
        "Art. 32",
        "Security of processing",
        "Appropriate technical and organizational measures protect personal data processing.",
    ),
    (
        "hipaa-security-rule",
        "164.312(a)(1)",
        "Access control",
        "Technical policies and procedures allow access only to authorized persons or software programs.",
    ),
)


def upgrade() -> None:
    bind = op.get_bind()
    op.execute(
        """
        create table if not exists compliance_controls (
            framework text not null,
            control_id text not null,
            title text not null,
            description text not null default '',
            primary key (framework, control_id)
        )
        """
    )
    for framework, control_id, title, description in CONTROLS:
        bind.execute(
            sa.text(
                """
            insert into compliance_controls (framework, control_id, title, description)
            values (:framework, :control_id, :title, :description)
            on conflict (framework, control_id) do update
                set title = excluded.title,
                    description = excluded.description
            """,
            ),
            {
                "framework": framework,
                "control_id": control_id,
                "title": title,
                "description": description,
            },
        )

    op.execute(
        """
        do $$
        begin
            if to_regclass('public.audit_log') is not null then
                alter table audit_log
                    add column if not exists evidence_controls jsonb not null default '[]'::jsonb;
            end if;

            if to_regclass('public.alerts') is not null then
                alter table alerts
                    add column if not exists evidence_controls jsonb not null default '[]'::jsonb;
            end if;

            if to_regclass('public.policy_documents') is not null then
                alter table policy_documents
                    add column if not exists evidence_controls jsonb not null default '[]'::jsonb;
            end if;

            if to_regclass('public.security_alerts') is not null then
                alter table security_alerts
                    add column if not exists evidence_controls jsonb not null default '[]'::jsonb;
            end if;
        end $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        do $$
        begin
            if to_regclass('public.security_alerts') is not null then
                alter table security_alerts drop column if exists evidence_controls;
            end if;

            if to_regclass('public.policy_documents') is not null then
                alter table policy_documents drop column if exists evidence_controls;
            end if;

            if to_regclass('public.alerts') is not null then
                alter table alerts drop column if exists evidence_controls;
            end if;

            if to_regclass('public.audit_log') is not null then
                alter table audit_log drop column if exists evidence_controls;
            end if;
        end $$;
        """
    )
    op.execute("drop table if exists compliance_controls")