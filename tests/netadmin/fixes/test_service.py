"""FixService: the full propose -> apply -> verify -> revert loop, fully offline.

Every controller seam is a fake: :class:`FakeDeviceReader` supplies the raw
device snapshot the planner needs, :class:`FakeControllerWriter` records the one
mutation an apply would send. Nothing here constructs a Real* seam, and a spy
proves it -- so the assertions double as a proof that no code path reached the
live controller. The store is a real migrated SQLite file seeded with a
``wifi.channel_plan`` issue on a 2.4 GHz radio (the canonical fixable finding).
"""

from __future__ import annotations

import pytest

from netadmin.domain.entities import Entity
from netadmin.domain.types import EntityType, FixState, IssueState
from netadmin.fixes import reader as reader_mod
from netadmin.fixes import writer as writer_mod
from netadmin.fixes.models import ConfirmTokenError, SafetyViolation, VerificationStatus
from netadmin.fixes.reader import FakeDeviceReader
from netadmin.fixes.service import FixService, IssueNotFound
from netadmin.fixes.writer import FakeControllerWriter
from netadmin.issues.engine import IssueEngine
from netadmin.issues.store_repository import StoreIssueRepository

from .conftest import AP_ID, AP_MAC, make_ap_device

pytestmark = pytest.mark.asyncio

NOW = 1_700_000_000


def _seed_channel_plan_issue(store, *, channel: int = 3) -> int:
    """An AP + its 2.4 GHz radio + an active off-grid channel_plan issue."""
    ap = store.upsert_entity(
        Entity(entity_type=EntityType.AP, native_id=AP_MAC, name="Office AP"), ts=NOW
    )
    radio = store.upsert_entity(
        Entity(
            entity_type=EntityType.RADIO,
            native_id=f"{AP_MAC}:ng",
            name="Office AP ng",
            parent_id=ap,
            meta={"band": "ng"},
        ),
        ts=NOW,
    )
    return store.insert_issue(
        fingerprint="fp-channel",
        detector_key="wifi.channel_plan",
        severity="p3",
        state="active",
        first_seen_ts=NOW,
        last_seen_ts=NOW,
        title="2.4 GHz off 1/6/11 on Office AP",
        entity_id=radio,
        evidence={"subtype": "channel_off_grid", "band": "2.4", "channel": channel},
    )


def _service(store, *, reader=None, writer=None) -> FixService:
    engine = IssueEngine(StoreIssueRepository(store))
    return FixService(
        store,
        engine,
        device_reader=(
            reader if reader is not None else FakeDeviceReader({AP_MAC: make_ap_device()})
        ),
        writer=writer,
        now_fn=lambda: NOW,
    )


def _no_real_seams(monkeypatch) -> list[str]:
    """Spy that records any attempt to construct a real (networked) seam."""
    built: list[str] = []
    real_writer_init = writer_mod.RealControllerWriter.__init__
    real_reader_init = reader_mod.RealDeviceReader.__init__

    def _spy_writer(self, client):
        built.append("writer")
        return real_writer_init(self, client)

    def _spy_reader(self, client):
        built.append("reader")
        return real_reader_init(self, client)

    monkeypatch.setattr(writer_mod.RealControllerWriter, "__init__", _spy_writer)
    monkeypatch.setattr(reader_mod.RealDeviceReader, "__init__", _spy_reader)
    return built


# --------------------------------------------------------------------------- #
# Dry run
# --------------------------------------------------------------------------- #
async def test_dry_run_renders_exact_payload_and_sends_nothing(store, monkeypatch):
    built = _no_real_seams(monkeypatch)
    issue_id = _seed_channel_plan_issue(store)
    writer = FakeControllerWriter()
    svc = _service(store, writer=writer)

    dry = await svc.dry_run(issue_id)

    assert writer.call_count == 0  # nothing sent
    assert store.list_changes(issue_id=issue_id) == []  # nothing ledgered
    assert dry.rendered[0]["endpoint"] == f"rest/device/{AP_ID}"
    assert dry.rendered[0]["method"] == "PUT"
    # off-grid channel 3 -> nearest of 1/6/11 == 1, other radios preserved
    table = dry.rendered[0]["payload"]["radio_table"]
    assert next(r for r in table if r["radio"] == "ng")["channel"] == 1
    assert any(r["radio"] == "na" for r in table)  # 5 GHz radio untouched, still present
    assert dry.confirm_token
    assert built == []  # no real seam ever constructed


async def test_dry_run_unknown_issue_raises(store):
    svc = _service(store)
    with pytest.raises(IssueNotFound):
        await svc.dry_run(4242)


# --------------------------------------------------------------------------- #
# Apply: gated, ledgered, verification armed
# --------------------------------------------------------------------------- #
async def test_apply_full_lifecycle_through_fake_writer(store, monkeypatch):
    built = _no_real_seams(monkeypatch)
    issue_id = _seed_channel_plan_issue(store)
    writer = FakeControllerWriter()
    svc = _service(store, writer=writer)

    dry = await svc.dry_run(issue_id)
    result = await svc.apply(issue_id, confirm_token=dry.confirm_token)

    # One mutation, through the fake writer, carrying the retuned channel.
    assert result.applied is True
    assert writer.call_count == 1
    sent = writer.calls[0]
    assert sent.method == "PUT"
    assert sent.endpoint == f"rest/device/{AP_ID}"
    assert next(r for r in sent.body["radio_table"] if r["radio"] == "ng")["channel"] == 1

    # Ledgered with before/after and marked applied.
    changes = store.list_changes(issue_id=issue_id)
    assert len(changes) == 1
    assert changes[0]["status"] == "applied"

    # The issue's fix_state advanced and the trail records fix_applied.
    issue = store.get_issue(issue_id)
    assert issue["fix_state"] == FixState.APPLIED.value
    kinds = [e["kind"] for e in store.list_issue_events(issue_id)]
    assert "fix_applied" in kinds

    # Verification window is armed and pending.
    v = svc.verification(issue_id)
    assert v.status is VerificationStatus.PENDING
    assert v.armed_ts == NOW

    assert built == []  # still no real seam


async def test_apply_with_wrong_token_is_refused_and_sends_nothing(store):
    issue_id = _seed_channel_plan_issue(store)
    writer = FakeControllerWriter()
    svc = _service(store, writer=writer)
    with pytest.raises(ConfirmTokenError):
        await svc.apply(issue_id, confirm_token="not-the-token")
    assert writer.call_count == 0
    assert store.list_changes(issue_id=issue_id) == []


async def test_apply_then_resolve_inside_window_verifies_fix(store):
    issue_id = _seed_channel_plan_issue(store)
    writer = FakeControllerWriter()
    engine = IssueEngine(StoreIssueRepository(store))
    svc = FixService(
        store,
        engine,
        device_reader=FakeDeviceReader({AP_MAC: make_ap_device()}),
        writer=writer,
        now_fn=lambda: NOW,
    )
    dry = await svc.dry_run(issue_id)
    await svc.apply(issue_id, confirm_token=dry.confirm_token)

    # The detector stops firing: clear the fingerprint K times to resolve, still
    # inside the 48 h verification window -> the fix is VERIFIED.
    fp = store.get_issue(issue_id)["fingerprint"]
    for i in range(engine.cfg.k_for("wifi.channel_plan")):
        engine.process_cycle(NOW + 60 * (i + 1), cleared=[fp])

    issue = store.get_issue(issue_id)
    assert issue["state"] == IssueState.RESOLVED.value
    assert issue["fix_state"] == FixState.VERIFIED.value
    assert svc.verification(issue_id).status is VerificationStatus.VERIFIED


# --------------------------------------------------------------------------- #
# Revert
# --------------------------------------------------------------------------- #
async def test_revert_restores_before_state(store):
    issue_id = _seed_channel_plan_issue(store)
    writer = FakeControllerWriter()
    svc = _service(store, writer=writer)
    dry = await svc.dry_run(issue_id)
    result = await svc.apply(issue_id, confirm_token=dry.confirm_token)
    change_id = result.change_ids[0]

    write = await svc.revert(change_id)

    assert write.ok
    # The revert PUT carries the ORIGINAL 2.4 GHz channel (back to 3).
    last = writer.calls[-1]
    assert last.endpoint == f"rest/device/{AP_ID}"
    assert next(r for r in last.body["radio_table"] if r["radio"] == "ng")["channel"] == 3
    assert store.get_change(change_id)["status"] == "reverted"


def _seed_min_rssi_issue(store) -> int:
    """An AP + its 2.4 GHz radio + an active min-RSSI-misconfig issue."""
    ap = store.upsert_entity(
        Entity(entity_type=EntityType.AP, native_id=AP_MAC, name="Office AP"), ts=NOW
    )
    radio = store.upsert_entity(
        Entity(
            entity_type=EntityType.RADIO,
            native_id=f"{AP_MAC}:ng",
            name="Office AP ng",
            parent_id=ap,
            meta={"band": "ng"},
        ),
        ts=NOW,
    )
    return store.insert_issue(
        fingerprint="fp-minrssi",
        detector_key="wifi.min_rssi_misconfig",
        severity="p2",
        state="active",
        first_seen_ts=NOW,
        last_seen_ts=NOW,
        title="min-RSSI set on Office AP",
        entity_id=radio,
        evidence={"reason": "mesh_uplink_ap", "on_mesh_ap": True},
    )


async def test_revert_refused_when_ap_is_now_a_mesh_uplink(store):
    # Apply a genuine min-RSSI removal, then the AP becomes a mesh uplink. Reverting
    # would re-enable min-RSSI on the mesh uplink -- the latent-outage case. The
    # service re-reads the (now mesh) device and the applier refuses; nothing is
    # sent beyond the original apply.
    issue_id = _seed_min_rssi_issue(store)
    writer = FakeControllerWriter()
    reader = FakeDeviceReader({AP_MAC: make_ap_device()})  # ng min_rssi_enabled=True
    svc = _service(store, reader=reader, writer=writer)

    dry = await svc.dry_run(issue_id)
    result = await svc.apply(issue_id, confirm_token=dry.confirm_token)
    assert result.applied is True
    change_id = result.change_ids[0]
    calls_after_apply = writer.call_count

    # The AP is now a wireless (mesh) uplink and min-RSSI has been removed (off).
    mesh_device = make_ap_device(
        radios=[
            {"radio": "ng", "channel": 3, "min_rssi_enabled": False, "min_rssi": 0},
            {"radio": "na", "channel": 36, "min_rssi_enabled": False, "min_rssi": 0},
        ]
    )
    mesh_device["uplink"] = {"type": "wireless"}
    reader.set_device(AP_MAC, mesh_device)

    with pytest.raises(SafetyViolation):
        await svc.revert(change_id)
    assert writer.call_count == calls_after_apply  # revert sent nothing
    assert store.get_change(change_id)["status"] != "reverted"


# --------------------------------------------------------------------------- #
# Advisory (physical) issue: no automatic fix, no controller contact
# --------------------------------------------------------------------------- #
async def test_advisory_issue_plans_manual_action_only(store, monkeypatch):
    built = _no_real_seams(monkeypatch)
    ap = store.upsert_entity(
        Entity(entity_type=EntityType.AP, native_id=AP_MAC, name="Office AP"), ts=NOW
    )
    port = store.upsert_entity(
        Entity(entity_type=EntityType.PORT, native_id=f"{AP_MAC}:5", parent_id=ap), ts=NOW
    )
    issue_id = store.insert_issue(
        fingerprint="fp-cable",
        detector_key="wired.bad_cable",
        severity="p2",
        state="active",
        first_seen_ts=NOW,
        last_seen_ts=NOW,
        title="rx_errors climbing on port 5",
        entity_id=port,
        evidence={"rx_errors_per_min": 42},
    )
    reader = FakeDeviceReader({AP_MAC: make_ap_device()})
    writer = FakeControllerWriter()
    svc = _service(store, reader=reader, writer=writer)

    dry = await svc.dry_run(issue_id)

    assert dry.manual_action_required is True
    assert dry.advisory
    assert dry.rendered == []
    # A physical fix reads no device and sends nothing.
    assert reader.calls == []
    assert writer.call_count == 0
    assert built == []
