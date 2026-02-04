"""Add blocked_ips table

Revision ID: e8a9b1c2d3f4
Revises: d5f9ff81772c
Create Date: 2026-01-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e8a9b1c2d3f4'
down_revision: Union[str, Sequence[str], None] = 'd5f9ff81772c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('blocked_ips',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('blocked_by', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_blocked_ips_id'), 'blocked_ips', ['id'], unique=False)
    op.create_index(op.f('ix_blocked_ips_ip_address'), 'blocked_ips', ['ip_address'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_blocked_ips_ip_address'), table_name='blocked_ips')
    op.drop_index(op.f('ix_blocked_ips_id'), table_name='blocked_ips')
    op.drop_table('blocked_ips')
