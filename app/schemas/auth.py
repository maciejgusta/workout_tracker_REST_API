from pydantic import BaseModel, Field
from datetime import datetime

class Token(BaseModel):
    access_token: str = Field(description="JWT access token.")
    token_type: str = Field(description="Token type.", examples=["bearer"])

class UserCreate(BaseModel):
    username: str = Field(description="Unique username.", examples=["John"])
    password: str = Field(
        min_length=8,
        description="Password (minimum 8 characters).",
        examples=["P4SSW0RD"],
    )

class UserOut(BaseModel):
    id: int = Field(description="User ID.")
    username: str = Field(description="Unique username.")
    created_at: datetime = Field(description="Account creation timestamp.")

    model_config = {"from_attributes": True}