from pydantic import BaseModel, Field

class ChangePassword(BaseModel):
    current_password: str = Field(description="Current password.")
    new_password: str = Field(
        min_length=8,
        description="New password (minimum 8 characters).",
    )
