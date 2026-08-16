"""002 Task Orchestration Priority and Timestamp Columns.

Revision ID: 002_task_orchestration
Revises: 001_initial_schema
Create Date: 2026-08-15 17:00:00.000000
"""

from collections.abc import Sequence

import alembic.op as op
import sqlalchemy as sa

revision: str = "002_task_orchestration"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    task_priority_enum = sa.Enum("LOW", "NORMAL", "HIGH", name="taskpriorityenum")
    task_priority_enum.create(op.get_bind(), checkfirst=True)

    op.add_column("tasks", sa.Column("created_by_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "fk_tasks_created_by_id_users",
        "tasks",
        "users",
        ["created_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "tasks",
        sa.Column("priority", task_priority_enum, nullable=False, server_default="NORMAL"),
    )
    op.add_column("tasks", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_tasks_status", "tasks", ["status"])


def downgrade() -> None:
    op.drop_index("ix_tasks_status", table_name="tasks")
    op.drop_column("tasks", "expires_at")
    op.drop_column("tasks", "completed_at")
    op.drop_column("tasks", "started_at")
    op.drop_column("tasks", "acknowledged_at")
    op.drop_column("tasks", "delivered_at")
    op.drop_column("tasks", "queued_at")
    op.drop_column("tasks", "priority")
    op.drop_constraint("fk_tasks_created_by_id_users", "tasks", type_="foreignkey")
    op.drop_column("tasks", "created_by_id")

    sa.Enum(name="taskpriorityenum").drop(op.get_bind(), checkfirst=True)
