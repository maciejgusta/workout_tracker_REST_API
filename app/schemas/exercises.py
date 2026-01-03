from pydantic import BaseModel, Field
from app.models.exercise import ExerciseMuscle, ExerciseEquipment
from datetime import datetime
from typing import Optional


class ExerciseCreate(BaseModel):
    name: str = Field(description="Unique name")
    primary_muscle: ExerciseMuscle = Field(description="Primary muscle group targeted")
    equipment: ExerciseEquipment = Field(description="Equipment used")
    is_active: bool = Field(default=True, description="Visible for users")


class ExerciseUpdate(BaseModel):
    name: Optional[str] = Field(default=None, description="Unique name")
    primary_muscle: Optional[ExerciseMuscle] = Field(
        default=None, description="Primary muscle group targeted"
    )
    equipment: Optional[ExerciseEquipment] = Field(
        default=None, description="Equipment used"
    )
    is_active: Optional[bool] = Field(default=None, description="Visible for users")


class ExerciseResponse(BaseModel):
    id: int = Field(description="Unique ID")
    name: str = Field(description="Unique name")
    primary_muscle: ExerciseMuscle = Field(description="Primary muscle group targeted")
    equipment: ExerciseEquipment = Field(description="Equipment used")
    is_active: Optional[bool] = Field(default=None, description="Visible for users")
    created_at: Optional[datetime] = Field(
        default=None, description="Creation timestamp"
    )
    updated_at: Optional[datetime] = Field(
        default=None, description="Last update timestamp"
    )

    model_config = {"from_attributes": True}


class ExercisesFilterParams(BaseModel):
    name: str | None = Field(
        default=None, description="Exercise name has to contain this phrase"
    )


class ExercisesListResponse(BaseModel):
    items: list[ExerciseResponse]
    total: int = Field(description="Total number of matching exercises")
    limit: int = Field(description="Items per page")
    offset: int = Field(description="Items to skip")
