"""infra.controller_down and infra.device_down, on synthetic poll_runs/events."""

from __future__ import annotations

from types import SimpleNamespace

from netadmin.detect.catalog import build_catalog
from netadmin.detect.context import DetectorContext
from netadmin.detect.detectors.infra import (
    KEY_CONTROLLER_DOWN,
    KEY_DEVICE_DOWN,
    ControllerDownDetector,
    DeviceDownDetector,
)
from netadmin.detect.engine import UNKNOWN
from netadmin.domain.entities import Entity
from netadmin.domain.types import Cadence, EntityType, IssueState, Severity
from netadmin.store.repository import Repository
from tests.netadmin.detect.support import (
    FakeBaselines,
    build_stack,
    entry,
    make_finding,
    seed_coverage,
    seed_device,
)

NOW = 4_000_000


def _ctx(repo: Repository, *, settings=None, now: int = NOW) -> DetectorContext:
    return DetectorContext(
        repo=repo,
        baselines=FakeBaselines(),
        now_ts=now,
        site_id="default",
        settings=settings,
    )


def _fail(repo: Repository, job: str, ts: int) -> None:
    repo.record_poll_run(job=job, ok=False, ts=ts, error="timeout")


def _ok(repo: Repository, job: str, ts: int) -> None:
    repo.record_poll_run(job=job, ok=True, ts=ts)


# ====================================================================== #
# infra.controller_down
# ====================================================================== #
def test_controller_down_fires_after_consecutive_failures(repo: Repository) -> None:
    _ok(repo, "fast_device", NOW - 240)
    for ts in (NOW - 180, NOW - 120, NOW - 60):
        _fail(repo, "fast_device", ts)

    findings = ControllerDownDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_CONTROLLER_DOWN
    assert f.severity is Severity.P1
    assert f.evidence["consecutive_failures"] == 3
    assert f.entity.native_id == "controller:default"
    assert f.entity.entity_id is None


def test_controller_down_quiet_below_threshold(repo: Repository) -> None:
    _ok(repo, "fast_device", NOW - 180)
    _fail(repo, "fast_device", NOW - 120)
    _fail(repo, "fast_device", NOW - 60)
    assert ControllerDownDetector().evaluate(_ctx(repo)) == []


def test_controller_down_clears_on_most_recent_success(repo: Repository) -> None:
    for ts in (NOW - 180, NOW - 120, NOW - 60):
        _fail(repo, "fast_device", ts)
    _ok(repo, "fast_device", NOW - 30)  # newest poll succeeded -> streak resets
    assert ControllerDownDetector().evaluate(_ctx(repo)) == []


def test_controller_down_quiet_with_no_polls(repo: Repository) -> None:
    assert ControllerDownDetector().evaluate(_ctx(repo)) == []


def test_controller_down_threshold_override(repo: Repository) -> None:
    settings = SimpleNamespace(
        thresholds={KEY_CONTROLLER_DOWN: {"consecutive_failures": 2}}, poll=None
    )
    _fail(repo, "fast_device", NOW - 120)
    _fail(repo, "fast_device", NOW - 60)
    findings = ControllerDownDetector().evaluate(_ctx(repo, settings=settings))
    assert len(findings) == 1
    assert findings[0].evidence["threshold"] == 2


def test_controller_down_is_not_gated_on_coverage(repo: Repository) -> None:
    # No successful polls at all (coverage 0) is precisely the fire condition, not
    # a reason to abstain: controller_down never returns UNKNOWN.
    for ts in (NOW - 180, NOW - 120, NOW - 60):
        _fail(repo, "fast_device", ts)
    result = ControllerDownDetector().evaluate(_ctx(repo))
    assert result is not UNKNOWN
    assert len(result) == 1


def test_controller_down_activates_and_inhibits_siblings(repo: Repository) -> None:
    from tests.netadmin.detect.support import StubDetector

    other = StubDetector("t.other", Cadence.FAST, lambda ctx: [make_finding("t.other")])
    catalog = build_catalog([entry(ControllerDownDetector(), ceiling=Severity.P1), entry(other)])
    stack = build_stack(repo, catalog=catalog)
    for ts in (NOW - 180, NOW - 120, NOW - 60):
        _fail(repo, "fast_device", ts)

    stack.detector_engine.run_fast(NOW)

    open_keys = {r["detector_key"]: r for r in repo.list_issues(open_only=True)}
    assert KEY_CONTROLLER_DOWN in open_keys
    # M=1 inhibition source -> active immediately, freezing everything else.
    assert open_keys[KEY_CONTROLLER_DOWN]["state"] == IssueState.ACTIVE.value
    assert "t.other" not in open_keys  # sibling finding was inhibited (global freeze)


# ====================================================================== #
# infra.device_down
# ====================================================================== #
def test_device_down_unknown_on_low_coverage(repo: Repository) -> None:
    seed_device(repo, native_id="sw-1", state="0", last_seen_ts=NOW)
    # Only two successful polls in a 10-slot window -> coverage 0.2 < 0.5.
    _ok(repo, "fast_device", NOW - 120)
    _ok(repo, "fast_device", NOW - 60)
    assert DeviceDownDetector().evaluate(_ctx(repo)) is UNKNOWN


def test_device_down_fires_on_offline_state(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    seed_device(repo, native_id="sw-1", name="sw-core", state="0", last_seen_ts=NOW)

    findings = DeviceDownDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_DEVICE_DOWN
    assert f.severity is Severity.P1
    assert f.entity.native_id == "sw-1"
    assert f.evidence["triggers"] == ["state_offline"]


def test_device_down_quiet_for_online_fresh_device(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    seed_device(repo, native_id="sw-1", state="1", last_seen_ts=NOW)
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_fires_on_unresolved_lost_contact(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    eid = seed_device(repo, native_id="sw-1", state="1", last_seen_ts=NOW)
    repo.record_event(ts=NOW - 100, key="EVT_SW_Lost_Contact", entity_id=eid)

    findings = DeviceDownDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].evidence["triggers"] == ["lost_contact"]
    assert findings[0].evidence["last_lost_contact_ts"] == NOW - 100


def test_device_down_reconnect_after_lost_clears(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    eid = seed_device(repo, native_id="sw-1", state="1", last_seen_ts=NOW)
    repo.record_event(ts=NOW - 200, key="EVT_SW_Lost_Contact", entity_id=eid)
    repo.record_event(ts=NOW - 100, key="EVT_SW_Connected", entity_id=eid)
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_stale_only_online_state_suppressed(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    # Online state but silent for 1000 s. This is the controller dropping the
    # device from stat/device for a few cycles (poll_runs stay ok=1), NOT a downed
    # device: staleness alone against a recorded-online state must not fire.
    seed_device(
        repo, native_id="ap-1", entity_type=EntityType.AP, state="1", last_seen_ts=NOW - 1000
    )
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_stale_only_no_state_fires(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    # No state ever recorded (None) + stale: nothing contradicts the silence, so
    # the stale signal still fires (the legitimate stale-only path survives).
    seed_device(repo, native_id="ap-1", entity_type=EntityType.AP, last_seen_ts=NOW - 1000)
    findings = DeviceDownDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].evidence["triggers"] == ["stale_last_seen"]


def test_device_down_stale_online_cascade_does_not_fire(repo: Repository) -> None:
    # The mass false-positive cascade of Finding 3: the controller returns an
    # empty/partial stat/device list for several cycles, every device's last_seen
    # goes stale while state stays online, coverage stays high (poll_runs ok=1) so
    # controller_down never inhibits. None of these may fire device_down.
    seed_coverage(repo, now=NOW)
    for i in range(9):
        seed_device(
            repo,
            native_id=f"ap-{i}",
            entity_type=EntityType.AP,
            state="1",
            last_seen_ts=NOW - 1000,
        )
    for i in range(3):
        seed_device(repo, native_id=f"sw-{i}", state="1", last_seen_ts=NOW - 1000)
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_transitional_state_suppresses_stale_only(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    # Provisioning (state 5) + silence is expected, not a failure.
    seed_device(
        repo, native_id="ap-1", entity_type=EntityType.AP, state="5", last_seen_ts=NOW - 1000
    )
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_offline_transitional_still_fires(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    # An explicit offline read is not suppressed even from a transitional-ish state:
    # here state is offline AND stale, so state_offline carries it.
    seed_device(
        repo, native_id="ap-1", entity_type=EntityType.AP, state="0", last_seen_ts=NOW - 1000
    )
    findings = DeviceDownDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert "state_offline" in findings[0].evidence["triggers"]


def test_device_down_ignores_clients(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    seed_device(repo, native_id="sw-1", state="1", last_seen_ts=NOW)  # healthy switch
    # A client that looks "offline" must be ignored: clients are not devices.
    seed_device(
        repo, native_id="client-mac", entity_type=EntityType.CLIENT, state="0", last_seen_ts=NOW
    )
    assert DeviceDownDetector().evaluate(_ctx(repo)) == []


def test_device_down_fires_per_device(repo: Repository) -> None:
    seed_coverage(repo, now=NOW)
    seed_device(repo, native_id="sw-1", state="0", last_seen_ts=NOW)
    seed_device(repo, native_id="ap-1", entity_type=EntityType.AP, state="0", last_seen_ts=NOW)
    findings = DeviceDownDetector().evaluate(_ctx(repo))
    assert {f.entity.native_id for f in findings} == {"sw-1", "ap-1"}


def test_device_down_activates_immediately_through_the_stack(repo: Repository) -> None:
    catalog = build_catalog([entry(DeviceDownDetector(), ceiling=Severity.P1)])
    stack = build_stack(repo, catalog=catalog)
    seed_coverage(repo, now=NOW)
    seed_device(repo, native_id="sw-1", state="0", last_seen_ts=NOW)

    stack.detector_engine.run_fast(NOW)
    issue = next(
        r for r in repo.list_issues(open_only=True) if r["detector_key"] == KEY_DEVICE_DOWN
    )
    assert issue["state"] == IssueState.ACTIVE.value  # M=1 inhibition source
    assert issue["severity"] == "p1"
