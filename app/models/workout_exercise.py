from app.db.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, TIMESTAMP, func, ForeignKey, UniqueConstraint
from datetime import datetime


class WorkoutExercise(Base):
    __tablename__ = "workout_exercises"
    __table_args__ = (
        UniqueConstraint(
            "workout_id",
            "position",
            name="uq_workout_exercises_workout_id_position",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        nullable=False,
    )
    workout_id: Mapped[int] = mapped_column(
        ForeignKey("workouts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    exercise_id: Mapped[int] = mapped_column(
        ForeignKey("exercises.id", ondelete="CASCADE"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
