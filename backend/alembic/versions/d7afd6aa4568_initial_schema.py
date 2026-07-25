"""initial schema

Revision ID: d7afd6aa4568
Revises: 
Create Date: 2026-07-24 20:21:51.746859

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'd7afd6aa4568'
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('alerts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source', sa.String(length=64), nullable=False),
    sa.Column('signature', sa.String(length=512), nullable=False),
    sa.Column('src_ip', sa.String(length=64), nullable=False),
    sa.Column('dst_ip', sa.String(length=64), nullable=False),
    sa.Column('src_port', sa.Integer(), nullable=True),
    sa.Column('dst_port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('attack_type', sa.String(length=32), nullable=True),
    sa.Column('ground_truth_label', sa.String(length=32), nullable=True),
    sa.Column('raw', sa.JSON(), nullable=False),
    sa.Column('total_duration_ms', sa.Integer(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_alerts_attack_type'), ['attack_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerts_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerts_src_ip'), ['src_ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerts_status'), ['status'], unique=False)
    op.create_index(
        'ix_alerts_timestamp_desc', 'alerts', [sa.text('timestamp DESC')], unique=False
    )
    op.create_index(
        'ix_alerts_severity_timestamp_desc',
        'alerts',
        ['severity', sa.text('timestamp DESC')],
        unique=False,
    )

    op.create_table('benchmark_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('sample_size', sa.Integer(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('results', sa.JSON(), nullable=True),
    sa.Column('agreement_rate', sa.Float(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('eval_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('sample_size', sa.Integer(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('overall', sa.JSON(), nullable=True),
    sa.Column('per_class', sa.JSON(), nullable=True),
    sa.Column('confusion_matrix', sa.JSON(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ioc_cache',
    sa.Column('indicator', sa.String(length=256), nullable=False),
    sa.Column('indicator_type', sa.String(length=16), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('malicious', sa.Boolean(), nullable=False),
    sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('indicator')
    )
    with op.batch_alter_table('ioc_cache', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ioc_cache_expires_at'), ['expires_at'], unique=False)

    op.create_table('enrichments',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('alert_id', sa.String(length=36), nullable=False),
    sa.Column('enriched_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('max_score', sa.Float(), nullable=True),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('enrichments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_enrichments_alert_id'), ['alert_id'], unique=False)

    op.create_table('remediations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('alert_id', sa.String(length=36), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('steps', sa.JSON(), nullable=False),
    sa.Column('techniques', sa.JSON(), nullable=False),
    sa.Column('reasoning', sa.Text(), nullable=True),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('remediations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_remediations_alert_id'), ['alert_id'], unique=False)

    op.create_table('traces',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('alert_id', sa.String(length=36), nullable=False),
    sa.Column('node', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('provider', sa.String(length=64), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('tokens_in', sa.Integer(), nullable=True),
    sa.Column('tokens_out', sa.Integer(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('traces', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_traces_alert_id'), ['alert_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('traces', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_traces_alert_id'))

    op.drop_table('traces')
    with op.batch_alter_table('remediations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_remediations_alert_id'))

    op.drop_table('remediations')
    with op.batch_alter_table('enrichments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_enrichments_alert_id'))

    op.drop_table('enrichments')
    with op.batch_alter_table('ioc_cache', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ioc_cache_expires_at'))

    op.drop_table('ioc_cache')
    op.drop_table('eval_runs')
    op.drop_table('benchmark_runs')
    op.drop_index('ix_alerts_severity_timestamp_desc', table_name='alerts')
    op.drop_index('ix_alerts_timestamp_desc', table_name='alerts')
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_alerts_status'))
        batch_op.drop_index(batch_op.f('ix_alerts_src_ip'))
        batch_op.drop_index(batch_op.f('ix_alerts_severity'))
        batch_op.drop_index(batch_op.f('ix_alerts_attack_type'))

    op.drop_table('alerts')
