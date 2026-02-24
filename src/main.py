import uvicorn
import logging
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

from .core.config import settings
from .core.redis_client import redis_client
from .middleware.rate_limit_middleware import RateLimitMiddleware
from .api.dashboard import router as dashboard_router
from .api.challenges import router as challenges_router
from .api.zones import router as zones_router
from .api.auth import router as auth_router
from .services.rate_limiter import RateLimiter
from .services.webhook_service import WebhookService
from .services.bot_detector import BotDetector
from .services.zone_service import ZoneService

# Configure structured logging
logging.basicConfig(level=logging.INFO)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Rate Limit Service", version=settings.app_version)
    try:
        await redis_client.connect()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error("Failed to connect to Redis on startup", error=str(e))
        # In debug mode, continue without Redis
        if not settings.debug:
            raise

    yield

    # Shutdown
    logger.info("Shutting down Rate Limit Service")
    try:
        await redis_client.disconnect()
    except Exception:
        pass  # Ignore disconnect errors


def create_application() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title="SentinelEdge",
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
        description="Enterprise Edge Security Platform - Cloudflare-style protection with AI-powered bot detection, real-time threat intelligence, and multi-tenant zone management.",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Add CORS middleware
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add rate limiting middleware
    rate_limiter = RateLimiter()
    bot_detector = BotDetector()
    zone_service = ZoneService()
    app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter, bot_detector=bot_detector, zone_service=zone_service)

    # Include routers
    app.include_router(dashboard_router)
    app.include_router(challenges_router)
    app.include_router(zones_router)
    app.include_router(auth_router)

    # Create services
    webhook_service = WebhookService()

    # Store services in app state for dependency injection
    app.state.rate_limiter = rate_limiter
    app.state.webhook_service = webhook_service
    app.state.bot_detector = bot_detector
    app.state.zone_service = zone_service

    return app


# Create the FastAPI app
app = create_application()


# Dependency functions for services
def get_rate_limiter(request: Request) -> RateLimiter:
    return request.app.state.rate_limiter


def get_webhook_service(request: Request) -> WebhookService:
    return request.app.state.webhook_service


def get_bot_detector(request: Request) -> BotDetector:
    return request.app.state.bot_detector


def get_zone_service(request: Request) -> ZoneService:
    return request.app.state.zone_service


# Example API endpoints (for testing rate limiting)
@app.get("/api/test")
async def test_endpoint():
    """Test endpoint with default rate limiting"""
    return {"message": "Request allowed", "status": "success"}


@app.get("/api/heavy")
async def heavy_endpoint():
    """Test endpoint that simulates heavy processing"""
    import asyncio
    await asyncio.sleep(0.1)  # Simulate work
    return {"message": "Heavy processing completed", "status": "success"}


@app.post("/auth/login")
async def login_endpoint():
    """Auth endpoint with strict rate limiting"""
    return {"message": "Login attempt processed", "status": "success"}


@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serve the landing page"""
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "index.html")
    try:
        with open(template_path, "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>Landing page not found</h1>", status_code=500)


@app.get("/api/v1/")
async def api_root():
    """API root endpoint"""
    return {
        "message": "SentinelEdge API v1",
        "version": settings.app_version,
        "docs": "/docs",
        "dashboard": "/dashboard" if settings.enable_dashboard else None,
        "zones": "/zones",
        "status": "operational",
        "endpoints": {
            "zones": "/api/v1/zones",
            "analytics": "/api/v1/analytics",
            "health": "/api/v1/health"
        }
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Serve the dashboard HTML page (protected)"""
    from .api.auth import get_current_user
    user = await get_current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/auth/login", status_code=302)

    if not settings.enable_dashboard:
        return HTMLResponse("<h1>Dashboard disabled</h1>", status_code=403)

    # Read the HTML template
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "dashboard.html")
    try:
        with open(template_path, "r") as f:
            content = f.read()
            # Inject user info into the template
            content = content.replace(
                '<div class="container">',
                f'''<div class="container">
                    <div class="user-info" style="background: var(--card-bg); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; border: 1px solid var(--border-color);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h3 style="color: var(--text-primary); margin: 0;">Welcome back, {user.name}!</h3>
                                <p style="color: var(--text-secondary); margin: 0.25rem 0 0 0;">{user.role.title()}</p>
                            </div>
                            <div style="display: flex; gap: 1rem;">
                                <a href="/zones" style="color: var(--accent-orange); text-decoration: none; font-weight: 500;">Manage Zones</a>
                                <form action="/auth/logout" method="post" style="display: inline;">
                                    <button type="submit" style="background: none; border: none; color: var(--text-secondary); cursor: pointer; font-weight: 500;">Logout</button>
                                </form>
                            </div>
                        </div>
                    </div>'''
            )
            return HTMLResponse(content)
    except FileNotFoundError:
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)


@app.get("/zones", response_class=HTMLResponse)
async def zones_page(request: Request):
    """Serve the zones management page (protected)"""
    from .api.auth import get_current_user
    user = await get_current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/auth/login", status_code=302)

    # Read the HTML template
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "zones.html")
    try:
        with open(template_path, "r") as f:
            content = f.read()
            # Inject user info into the template
            content = content.replace(
                '<div class="container">',
                f'''<div class="container">
                    <div class="user-info" style="background: var(--card-bg); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; border: 1px solid var(--border-color);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h3 style="color: var(--text-primary); margin: 0;">{user.name}</h3>
                                <p style="color: var(--text-secondary); margin: 0.25rem 0 0 0;">{user.role.title()}</p>
                            </div>
                            <div style="display: flex; gap: 1rem;">
                                <a href="/dashboard" style="color: var(--accent-orange); text-decoration: none; font-weight: 500;">Dashboard</a>
                                <form action="/auth/logout" method="post" style="display: inline;">
                                    <button type="submit" style="background: none; border: none; color: var(--text-secondary); cursor: pointer; font-weight: 500;">Logout</button>
                                </form>
                            </div>
                        </div>
                    </div>'''
            )
            return HTMLResponse(content)
    except FileNotFoundError:
        return HTMLResponse("<h1>Zones page not found</h1>", status_code=500)


@app.get("/docs", response_class=HTMLResponse)
async def api_docs_page():
    """Serve the API documentation page"""
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "docs.html")
    try:
        with open(template_path, "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>API docs not found</h1>", status_code=500)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Serve the user settings page (protected)"""
    from .api.auth import get_current_user
    user = await get_current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/auth/login", status_code=302)

    # Read the HTML template
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "settings.html")
    try:
        with open(template_path, "r") as f:
            content = f.read()
            # Inject user info into the template
            content = content.replace("{{ user.name }}", user.name or "")
            content = content.replace("{{ user.email }}", user.email)
            content = content.replace("{{ user.role }}", user.role)
            content = content.replace("{{ user.email_verified }}", "true" if user.email_verified else "false")
            return HTMLResponse(content)
    except FileNotFoundError:
        return HTMLResponse("<h1>Settings page not found</h1>", status_code=500)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=settings.workers,
        log_level="info"
    )