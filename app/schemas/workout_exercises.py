from pydantic import BaseModel, Field
from datetime import datetime


class WorkoutExercisesResponse(BaseModel):
    id: int = Field(description="Workout exercise ID")
    workout_id: int = Field(description="Workout ID")
    exercise_id: int = Field(description="Exercise ID")
    position: int = Field(description="Exercise order in the workout")
    created_at: datetime | None = Field(default=None, description="Creation timestamp")
    updated_at: datetime | None = Field(
        default=None, description="Last update timestamp"
    )

    model_config = {"from_attributes": True}


class WorkoutExerciseCreate(BaseModel):
    exercise_id: int = Field(description="Exercise ID")
    position: int | None = Field(
        default=None, ge=1, description="Position of exercise in the workout"
    )


class WorkoutExerciseUpdate(BaseModel):
    exercise_id: int | None = Field(default=None, description="Exercise ID")
    position: int | None = Field(
        default=None, ge=1, description="Position of exercise in the workout"
    )
