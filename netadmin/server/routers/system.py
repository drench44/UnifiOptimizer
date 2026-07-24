"""System router: ``GET /api/health`` + the access-token surface (ARCHITECTURE.md 12 & 18.1).

``GET /api/health`` is the one endpoint an operator (or a probe) hits to know the
daemon is alive and honest: last-successful-poll age per collector job, WebSocket
listener state, per-job consecutive failures, database size, entity counts, and
uptime. The composition lives in :mod:`netadmin.server.runtime`; this router only
wires it to HTTP and always answers 200 with an honest body (a status endpoint
that refuses to answer when the system is unhealthy defeats its own purpose).

The two ``/system/token`` routes are how a user finds or rotates their access
token (ARCHITECTURE.md 18.1 Settings addendum) -- the token a just-in-time fix
prompt asks for. Their auth is enforced by the middleware, not here:

* ``GET /system/token`` (reveal) returns the current token. Sensitive, so the
  middleware gates it behind the bearer token OR a loopback peer.
* ``POST /system/token/regenerate`` mints a new token, persists it, and returns it
  once. A gated, rate-limited mutation (the middleware requires the *current*
  token before this runs).

The health handler is ``async`` deliberately: the store's SQLite connection is
bound to the event-loop thread (one process, shared loop -- section 3), so it must
be read on that thread, not a threadpool worker. Local read queries are cheap and
do not warrant the executor (heavy analysis does; section 3).
"""

from __future__ import annotations

from secrets import token_urlsafe
from typing import Any

from fastapi import APIRouter, Request

from netadmin.config import SECRETS_ENV, write_secrets
from netadmin.server.runtime import build_health

router = APIRouter(prefix="/api", tags=["system"])

# CSPRNG entropy for a regenerated access token; matches the first-run mint
# (netadmin/server/routers/setup.py) so both paths produce the same shape.
_TOKEN_BYTES = 32


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    """Daemon health snapshot (section 12). Never raises; missing data is UNKNOWN."""
    app = request.app
    return build_health(app.state.store, app.state.daemon, app.state.settings)


@router.get("/system/token")
async def reveal_token(request: Request) -> dict[str, Any]:
    """Reveal the current access token (ARCHITECTURE.md 18.1).

    The auth middleware has already enforced access (bearer token or loopback); this
    handler only reads the token back so Settings can show it. ``token`` is ``null``
    on an unconfigured / open install (there is nothing to reveal).
    """
    token = request.app.state.settings.api_token
    return {"token": token, "configured": token is not None}


@router.post("/system/token/regenerate")
async def regenerate_token(request: Request) -> dict[str, Any]:
    """Mint a new access token, persist it, and return it once (ARCHITECTURE.md 18.1).

    Gated + rate limited by the middleware, which required the *current* token
    before this ran. The new token is written to ``secrets.env`` (600, atomic, every
    other key preserved) and applied to the live ``Settings`` in place, so the
    middleware's token provider locks to it immediately -- the browser must store
    the returned value to keep applying fixes.
    """
    app = request.app
    settings = app.state.settings
    new_token = token_urlsafe(_TOKEN_BYTES)
    write_secrets(
        {"NETADMIN_API_TOKEN": new_token},
        path=getattr(app.state, "secrets_path", None) or SECRETS_ENV,
    )
    settings.netadmin_api_token = new_token
    return {"token": new_token}


__all__ = ["router"]
