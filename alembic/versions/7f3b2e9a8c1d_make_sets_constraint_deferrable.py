"""make sets constraint deferrable

Revision ID: 7f3b2e9a8c1d
Revises: 0d6d6d8b8d6c
Create Date: 2026-01-03 16:30:00.000000

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "7f3b2e9a8c1d"
down_revision: Union[str, Sequence[str], None] = "0d6d6d8b8d6c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint(
        "uq_sets_workout_exercise_set_index",
        "sets",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_sets_workout_exercise_set_index",
        "sets",
        ["workout_exercise_id", "set_index"],
        deferrable=True,
        initially="DEFERRED",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "uq_sets_workout_exercise_set_index",
        "sets",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_sets_workout_exercise_set_index",
        "sets",
        ["workout_exercise_id", "set_index"],
    )
