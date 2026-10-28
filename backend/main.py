"""
Main application entry point for SERC (Security Event Response Copilot).
Launches FastAPI with CORS, API routes, and serves the clean light-themed UI.
"""
import sys
import logging
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is in sys.path when executed directly as `python backend/main.py`
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import settings
from backend.routes.alerts import router as alerts_router
from backend.services.retrieval_service import retrieval_service

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("serc.main")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: checks system health and vector store on startup."""
    logger.info("Initializing SERC (Security Event Response Copilot)...")
    logger.info(f"Environment: {settings.environment} | Mock Mode: {settings.is_mock}")
    try:
        stats = retrieval_service.get_stats()
        logger.info(f"Vector Store Status: {stats.get('total_vectors', 0)} vectors available in collection '{settings.qdrant_collection}'")
    except Exception as e:
        logger.warning(f"Vector store initial check warning: {e}")
    yield
    logger.info("Shutting down SERC.")


app = FastAPI(
    title="SERC — Security Event Response Copilot",
    description="Wazuh Security Event Response Copilot powered by RAG and Evidence-Backed Validation.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins() or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API endpoints
app.include_router(alerts_router)

# Mount frontend files if directory exists
if FRONTEND_DIR.exists():
    # Serve index.html at root
    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Frontend index.html not found"}

    # Mount static assets (style.css, script.js)
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    # Also mount root static so relative paths like "style.css" and "script.js" resolve directly
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting SERC server on http://{settings.host}:{settings.port}")
    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=True, app_dir=str(PROJECT_ROOT))
