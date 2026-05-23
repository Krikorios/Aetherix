"""Backfill and constrain customers.company_type

Revision ID: 20260519_0001
Revises: 
Create Date: 2026-05-19 20:15:00
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260519_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        do $$
        begin
            if to_regclass('public.customers') is not null then
                alter table customers
                    add column if not exists company_type text not null default 'customer';

                update customers
                set company_type = 'customer'
                where company_type is null or company_type not in ('partner', 'customer');

                alter table customers alter column company_type set default 'customer';
                alter table customers alter column company_type set not null;

                if not exists (
                    select 1
                    from pg_constraint
                    where conname = 'customers_company_type_check'
                      and conrelid = 'customers'::regclass
                ) then
                    alter table customers
                    add constraint customers_company_type_check
                    check (company_type in ('partner', 'customer'));
                end if;
            end if;
        end $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        do $$
        begin
            if to_regclass('public.customers') is not null then
                if exists (
                    select 1
                    from pg_constraint
                    where conname = 'customers_company_type_check'
                      and conrelid = 'customers'::regclass
                ) then
                    alter table customers drop constraint customers_company_type_check;
                end if;
            end if;
        end $$;
        """
    )
