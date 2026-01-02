from fastapi import FastAPI
from app.routers import auth, users, exercises
from importlib.metadata import version

APP_VERSION = version("workout-tracker-api")

app = FastAPI(
    title="Workout Tracker API",
    version=APP_VERSION,
    description="check README.md"
)

app.include_router(auth.router, prefix="/v1")
app.include_router(users.router, prefix="/v1")
app.include_router(exercises.router, prefix="/v1")

@app.get("/")
async def root():
    return {"message": "Hello World"}