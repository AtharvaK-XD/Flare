"""benchmark_runs: disagreement examples column

The agreement rate is only credible with the disagreeing alerts attached, so they
are stored alongside the run rather than recomputed or discarded.

Revision ID: c4d1a7e93b02
Revises: b2c9e41f70a3
Create Date: 2026-07-25 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'c4d1a7e93b02'
down_revision: str | Sequence[str] | None = 'b2c9e41f70a3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('benchmark_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('disagreement_examples', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('benchmark_runs', schema=None) as batch_op:
        batch_op.drop_column('disagreement_examples')
