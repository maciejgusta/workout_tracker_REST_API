from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.routers import auth, users, exercises, workouts, health
from app.core.config import get_settings
from app.core.logging import configure_logging
import tomllib
from app.middleware import get_logging_middleware

logger = configure_logging()

with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
    APP_VERSION = data["project"]["version"]


@asynccontextmanager  # validate settings on runtime
async def lifespan(_: FastAPI):
    get_settings()
    yield


app = FastAPI(
    title="Workout Tracker API",
    version=APP_VERSION,
    description="check README.md",
    lifespan=lifespan,
)

app.include_router(auth.router, prefix="/v1")
app.include_router(users.router, prefix="/v1")
app.include_router(exercises.router, prefix="/v1")
app.include_router(workouts.router, prefix="/v1")
app.include_router(health.router)

app.middleware("http")(get_logging_middleware(logger))
