from pydantic import BaseModel, Field
from datetime import datetime


class WorkoutResponse(BaseModel):
    id: int = Field(description="Unique ID")
    user_id: int | None = Field(default=None, description="Creator ID")
    name: str = Field(description="Displayed name")
    created_at: datetime | None = Field(default=None, description="Creation timestamp")
    updated_at: datetime | None = Field(
        default=None, description="Last update timestamp"
    )

    model_config = {"from_attributes": True}


class WorkoutCreate(BaseModel):
    name: str = Field(min_length=1, description="Displayed name")
    user_id: int | None = Field(
        default=None, description="Target user ID: Only for admin"
    )


class WorkoutUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, description="Displayed name")
