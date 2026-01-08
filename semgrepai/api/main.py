"""FastAPI application for SemgrepAI web UI."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .db import init_db
from .routes import api_router
from ..config import ConfigManager
from ..logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting SemgrepAI API server...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down SemgrepAI API server...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = ConfigManager().config

    app = FastAPI(
        title="SemgrepAI",
        description="AI-powered Semgrep vulnerability validator with web UI",
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "version": "0.2.0"}

    # Serve frontend static files if they exist
    frontend_dist = Path(__file__).parent.parent / "web" / "frontend" / "dist"
    if frontend_dist.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(frontend_dist / "assets")),
            name="assets",
        )

        @app.get("/")
        async def serve_frontend():
            """Serve the frontend application."""
            return FileResponse(str(frontend_dist / "index.html"))

        @app.get("/{path:path}")
        async def serve_frontend_routes(path: str):
            """Serve frontend routes (SPA fallback)."""
            # Check if it's an API route
            if path.startswith("api/") or path.startswith("ws/"):
                return {"detail": "Not Found"}

            # Check if file exists in dist
            file_path = frontend_dist / path
            if file_path.exists() and file_path.is_file():
                return FileResponse(str(file_path))

            # Fallback to index.html for SPA routing
            return FileResponse(str(frontend_dist / "index.html"))
    else:
        @app.get("/")
        async def no_frontend():
            """Placeholder when frontend is not built."""
            return {
                "message": "SemgrepAI API is running",
                "docs": "/api/docs",
                "frontend": "Frontend not built. Run 'cd semgrepai/web/frontend && npm run build'",
            }

    return app


# Create the application instance
app = create_app()
