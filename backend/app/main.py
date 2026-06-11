from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db, get_db
from app.security import get_session
from app.routers import auth, credentials, health
from app.routers import investigate, vt, analyse, hunt, session_state, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SudoTrace",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Paths an analyst who still owes a password change may reach. Everything
# else under /api is gated until they change the default password — the
# frontend already redirects to the change-password screen, but a scripted
# client (or anyone reaching the API directly) would otherwise have a fully
# capable session. This is the single server-side choke point for that rule.
_MUST_CHANGE_ALLOWLIST = frozenset({
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/change-password",
    "/api/health",
})


@app.middleware("http")
async def enforce_password_change(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in _MUST_CHANGE_ALLOWLIST:
        session_id = request.cookies.get("session_id")
        if session_id:
            db = get_db()
            try:
                sess = get_session(session_id, db)
            finally:
                db.close()
            # Only block a *valid* session that still owes a change; an
            # absent/expired session falls through so the route returns its
            # own 401 (don't change that contract here).
            if sess is not None and sess["must_change_password"]:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Password change required before using this feature."},
                )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "https://127.0.0.1"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth")
app.include_router(credentials.router, prefix="/api/credentials")
app.include_router(investigate.router, prefix="/api/investigate")
app.include_router(analyse.router,    prefix="/api/analyse")
app.include_router(vt.router,         prefix="/api/vt")
app.include_router(hunt.router,       prefix="/api/hunt")
app.include_router(session_state.router, prefix="/api/session")
app.include_router(admin.router,          prefix="/api/admin")
