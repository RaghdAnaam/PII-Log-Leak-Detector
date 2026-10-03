"""
PII Log Leak Detector — FastAPI application.

Security decisions:
- CORS is restricted to known frontend origins (localhost dev ports).
- Security headers are added to every response to prevent common web vulnerabilities.
- Uploaded files are never executed — only read as text and scanned.
- matched_value is never serialized in API responses (enforced by response models).
- Scan results are stored in memory only and cleared on restart.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes_health import router as health_router
from backend.app.api.routes_scan import router as scan_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="PII Log Leak Detector",
        description="Detects potential PII accidentally exposed in source code and log files.",
        version="1.0.0",
    )

    # In-memory scan result store — stateless, cleared on restart
    app.state.scan_results = {}

    # CORS — allow frontend dev servers
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    app.include_router(health_router)
    app.include_router(scan_router)

    return app


app = create_app()
