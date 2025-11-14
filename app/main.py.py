# app/main.py
import os
from fastapi import FastAPI
from .routes import jobs, outputs

app = FastAPI(title="StoltzCo SmartBuild Webapp")

app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(outputs.router, prefix="/outputs", tags=["outputs"])


@app.get("/health")
def health_check():
    return {"status": "ok"}