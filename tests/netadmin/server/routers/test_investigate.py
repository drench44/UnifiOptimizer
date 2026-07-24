"""ASGI-transport tests for the LLM-investigator endpoints on the issues router."""

from __future__ import annotations

import httpx
import pytest
import respx

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _isolate_dossier_dir(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch):
    """Keep the manual provider's dossier files out of the repo tree.

    The ``manual`` provider defaults to writing under ``<project>/investigations``;
    redirect every test in this module to a throwaway temp dir so a manual
    ``investigate`` never pollutes the working copy.
    """
    import netadmin.llm.manual as manual_mod

    tmp = tmp_path_factory.mktemp("dossiers")
    monkeypatch.setattr(manual_mod, "default_base_dir", lambda: tmp)


async def _client(app: object) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _active_issue_id(c: httpx.AsyncClient) -> int:
    listing = (await c.get("/api/issues", params={"state": "active"})).json()
    return listing["issues"][0]["id"]


async def test_list_providers(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    async with await _client(app) as c:
        resp = await c.get("/api/issues/investigate/providers")
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()["providers"]}
    assert names == {"manual", "copilot", "anthropic"}
    manual = next(p for p in resp.json()["providers"] if p["name"] == "manual")
    assert manual["available"] is True


async def test_manual_investigate_is_pending_then_listed(app: object) -> None:
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        created = await c.post(f"/api/issues/{issue_id}/investigate", json={"provider": "manual"})
        assert created.status_code == 200
        inv = created.json()["investigation"]
        assert inv["status"] == "pending"
        assert inv["provider"] == "manual"
        assert "Investigation dossier" in inv["dossier_md"]

        listing = await c.get(f"/api/issues/{issue_id}/investigations")
        assert listing.status_code == 200
        assert listing.json()["count"] == 1

        # the 'investigated' event landed on the issue's trail
        detail = (await c.get(f"/api/issues/{issue_id}")).json()
        assert "investigated" in [e["kind"] for e in detail["events"]]


async def test_import_round_trip(app: object) -> None:
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        await c.post(f"/api/issues/{issue_id}/investigate", json={"provider": "manual"})
        response_md = "## Answers\n### Root cause\nA failing cable."
        imported = await c.post(
            f"/api/issues/{issue_id}/investigations/import", json={"text": response_md}
        )
        assert imported.status_code == 200
        inv = imported.json()["investigation"]
        assert inv["status"] == "answered"
        assert inv["response_md"] == response_md


async def test_import_requires_text(app: object) -> None:
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        resp = await c.post(f"/api/issues/{issue_id}/investigations/import", json={"text": ""})
    assert resp.status_code == 422


async def test_investigate_unknown_issue_404(app: object) -> None:
    async with await _client(app) as c:
        a = await c.post("/api/issues/999999/investigate", json={"provider": "manual"})
        b = await c.get("/api/issues/999999/investigations")
        d = await c.post("/api/issues/999999/investigations/import", json={"text": "x"})
    assert a.status_code == 404
    assert b.status_code == 404
    assert d.status_code == 404


async def test_investigate_anthropic_absent_key_is_400(
    app: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        resp = await c.post(f"/api/issues/{issue_id}/investigate", json={"provider": "anthropic"})
    assert resp.status_code == 400


@respx.mock
async def test_investigate_anthropic_happy_path(
    app: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "## Answers\n### Root cause\nCable."}],
            },
        )
    )
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        resp = await c.post(f"/api/issues/{issue_id}/investigate", json={"provider": "anthropic"})
    assert resp.status_code == 200
    inv = resp.json()["investigation"]
    assert inv["status"] == "answered"
    assert inv["response_md"] == "## Answers\n### Root cause\nCable."


@respx.mock
async def test_investigate_provider_runtime_error_is_502(
    app: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(500, json={"error": {"message": "overloaded"}})
    )
    async with await _client(app) as c:
        issue_id = await _active_issue_id(c)
        resp = await c.post(f"/api/issues/{issue_id}/investigate", json={"provider": "anthropic"})
    assert resp.status_code == 502
