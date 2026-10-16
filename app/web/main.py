"""The web app: landing page, signup, dashboard, billing.

Run with:  uv run uvicorn app.web.main:app --reload
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.db import create_all
from app.web.deps import LoginRequired, redirect, render


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO)
    create_all()
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title=s.app_name, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=s.secret_key,
        session_cookie="session",
        max_age=30 * 24 * 3600,
        same_site="lax",
        https_only=s.session_cookie_secure,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if s.session_cookie_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp

    static = Path(__file__).resolve().parent.parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    from app.web import routes_admin, routes_auth, routes_billing, routes_dashboard, routes_public

    for module in (routes_public, routes_auth, routes_dashboard, routes_billing, routes_admin):
        app.include_router(module.router)

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return redirect(f"/login?next={quote(request.url.path)}")

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith(("/billing/webhook", "/api/")):
            return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
        return render(request, "error.html", status_code=exc.status_code, code=exc.status_code, detail=exc.detail)

    return app


app = create_app()
