from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import Integer, String, TIMESTAMP, Boolean, func, text
from sqlalchemy import Enum as SAEnum
from datetime import datetime
from enum import Enum
from app.db.database import Base


class ExerciseMuscle(str, Enum):
    CHEST = "chest"
    BACK = "back"
    TRICEPS = "triceps"
    BICEPS = "biceps"
    ABS = "abs"
    LEGS = "legs"


class ExerciseEquipment(str, Enum):
    BARBELL = "barbell"
    DUMBBELL = "dumbbell"
    MACHINE = "machine"
    CABLE = "cable"
    KETTLEBELL = "kettlebell"
    BODYWEIGHT = "bodyweight"
    OTHER = "other"


class Exercise(Base):
    __tablename__ = "exercises"
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, nullable=False, autoincrement=True
    )
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    primary_muscle: Mapped[ExerciseMuscle] = mapped_column(
        SAEnum(
            ExerciseMuscle,
            name="exercise_muscle",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    equipment: Mapped[ExerciseEquipment] = mapped_column(
        SAEnum(
            ExerciseEquipment,
            name="exercise_equipment",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
