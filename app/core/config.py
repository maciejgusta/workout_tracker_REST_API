from functools import lru_cache
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = Field()
    JWT_SECRET: SecretStr = Field()
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_ISSUER: str = Field(default="workout_tracker_api")
    JWT_AUDIENCE: str = Field(default="workout_tracker")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, gt=0)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=1, gt=0)
    COOKIE_SECURE: bool = Field(default=False)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
