"""003 Phase 7 Findings Domain and Evidence Schema Enhancements.

Revision ID: 003_phase_7_findings
Revises: 002_task_orchestration
Create Date: 2026-08-16 02:00:00.000000
"""

from collections.abc import Sequence

import alembic.op as op
import sqlalchemy as sa

revision: str = "003_phase_7_findings"
down_revision: str | None = "002_task_orchestration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add new columns to findings table
    op.add_column("findings", sa.Column("device_id", sa.String(length=36), nullable=True))
    op.add_column("findings", sa.Column("task_id", sa.String(length=36), nullable=True))
    op.add_column("findings", sa.Column("execution_id", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("capability", sa.String(length=100), nullable=True))
    op.add_column("findings", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    # 2. Foreign keys for findings
    op.create_foreign_key(
        "fk_findings_device_id_devices",
        "findings",
        "devices",
        ["device_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_findings_task_id_tasks", "findings", "tasks", ["task_id"], ["id"], ondelete="SET NULL"
    )

    # 3. Indexes for finding filtering & performance
    op.create_index("ix_findings_device_id", "findings", ["device_id"])
    op.create_index("ix_findings_task_id", "findings", ["task_id"])
    op.create_index("ix_findings_execution_id", "findings", ["execution_id"])
    op.create_index("ix_findings_capability", "findings", ["capability"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])


def downgrade() -> None:
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_capability", table_name="findings")
    op.drop_index("ix_findings_execution_id", table_name="findings")
    op.drop_index("ix_findings_task_id", table_name="findings")
    op.drop_index("ix_findings_device_id", table_name="findings")

    op.drop_constraint("fk_findings_task_id_tasks", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_device_id_devices", "findings", type_="foreignkey")

    op.drop_column("findings", "updated_at")
    op.drop_column("findings", "created_at")
    op.drop_column("findings", "remediation")
    op.drop_column("findings", "description")
    op.drop_column("findings", "capability")
    op.drop_column("findings", "execution_id")
    op.drop_column("findings", "task_id")
    op.drop_column("findings", "device_id")
