"""make workout_exercises position constraint deferrable

Revision ID: 0d6d6d8b8d6c
Revises: 9617e1015e97
Create Date: 2026-01-03 15:15:00.000000

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0d6d6d8b8d6c"
down_revision: Union[str, Sequence[str], None] = "9617e1015e97"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint(
        "uq_workout_exercises_workout_id_position",
        "workout_exercises",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_workout_exercises_workout_id_position",
        "workout_exercises",
        ["workout_id", "position"],
        deferrable=True,
        initially="DEFERRED",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "uq_workout_exercises_workout_id_position",
        "workout_exercises",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_workout_exercises_workout_id_position",
        "workout_exercises",
        ["workout_id", "position"],
    )
