"""eval_runs: attack-type metrics column

Severity and attack type are two independent evaluation targets. The existing
overall/per_class/confusion_matrix columns hold the severity report; this column
holds the attack-type report so the second half of the result is stored rather
than discarded.

Revision ID: b2c9e41f70a3
Revises: d7afd6aa4568
Create Date: 2026-07-25 11:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'b2c9e41f70a3'
down_revision: str | Sequence[str] | None = 'd7afd6aa4568'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('eval_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('attack_type_metrics', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('eval_runs', schema=None) as batch_op:
        batch_op.drop_column('attack_type_metrics')
