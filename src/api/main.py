"""Main FastAPI application. Run with: uvicorn src.api.main:app --reload --port 8000"""
from __future__ import annotations
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from src.dbs import silo_a, silo_b
from src.api import transactions, telemetry, admin

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: make sure both silo databases exist before serving requests
    silo_a.init_db()
    silo_b.init_db()
    yield
    # Shutdown: nothing to clean up (SQLite connections are per-request)


app = FastAPI(
    title="FinSpark Fraud Detection Engine",
    description="Transient Cross-Silo Correlation fraud + HNDL detection API",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the dashboard (served from a different port/origin during dev) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(transactions.router)
app.include_router(telemetry.router)
app.include_router(admin.router)


@app.middleware("http")
async def no_cache_headers(request, call_next):
    response = await call_next(request)
    if request.url.path in ("/stats", "/audit", "/health"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.get("/", tags=["root"])
def root():
    return {
        "service": "FinSpark Fraud Detection Engine",
        "status": "running",
        "docs": "/docs",
        "dashboard": "/dashboard",
    }


@app.get("/dashboard", tags=["root"])
def dashboard():
    return FileResponse(STATIC_DIR / "dashboard.html")
