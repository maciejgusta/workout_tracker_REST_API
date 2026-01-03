from pydantic import BaseModel, Field
from datetime import datetime


class SetResponse(BaseModel):
    id: int = Field(description="Set ID")
    workout_exercise_id: int = Field(description="Workout exercise ID")
    set_index: int = Field(description="Order of the set within the exercise")
    weight: float | None = Field(default=None, description="Weight used")
    repetitions: int = Field(description="Number of repetitions")
    rpe: int | None = Field(default=None, description="Rate of perceived exertion")
    created_at: datetime | None = Field(default=None, description="Creation timestamp")
    updated_at: datetime | None = Field(
        default=None, description="Last update timestamp"
    )

    model_config = {"from_attributes": True}


class SetCreate(BaseModel):
    set_index: int | None = Field(
        default=None, ge=1, description="Set order in the exercise"
    )
    weight: float | None = Field(default=None, description="Weight used")
    repetitions: int = Field(ge=1, description="Number of repetitions")
    rpe: int | None = Field(
        default=None, ge=1, le=10, description="Rate of perceived exertion"
    )


class SetUpdate(BaseModel):
    set_index: int | None = Field(
        default=None, ge=1, description="Set order in the exercise"
    )
    weight: float | None = Field(default=None, description="Weight used")
    repetitions: int | None = Field(
        default=None, ge=1, description="Number of repetitions"
    )
    rpe: int | None = Field(
        default=None, ge=1, le=10, description="Rate of perceived exertion"
    )
