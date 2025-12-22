from fastapi import FastAPI
from app.routers import auth

app = FastAPI()

app.include_router(auth.router, prefix="/v1")

@app.get("/")
async def root():
    return {"message": "Hello World"}