from app.db.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, Float, TIMESTAMP, func, ForeignKey, UniqueConstraint
from datetime import datetime


class Set(Base):
    __tablename__ = "sets"
    __table_args__ = (
        UniqueConstraint(
            "workout_exercise_id",
            "set_index",
            name="uq_sets_workout_exercise_set_index",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, nullable=False
    )
    workout_exercise_id: Mapped[int] = mapped_column(
        ForeignKey("workout_exercises.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    set_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    repetitions: Mapped[int] = mapped_column(Integer, nullable=False)
    rpe: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
