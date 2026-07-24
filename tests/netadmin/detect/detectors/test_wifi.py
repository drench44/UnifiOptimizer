"""wifi.* detectors on synthetic radios/clients/events/samples.

Each detector gets, at minimum, a firing case, a confounder-suppressed case, and
an UNKNOWN-coverage case (ARCHITECTURE.md sections 4 & 6). Fixtures are built from
the real temp-DB :class:`Repository` so the detectors run against the same store
seam they use in production.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

from netadmin.detect.context import DetectorContext
from netadmin.detect.detectors.wifi import (
    KEY_AIRTIME_SATURATION,
    KEY_BAND_STEERING,
    KEY_CHANNEL_PLAN,
    KEY_DFS_RECURRING,
    KEY_LEGACY_RATES,
    KEY_MESH_UPLINK,
    KEY_MIN_RSSI_MISCONFIG,
    KEY_PINGPONG_ROAMER,
    KEY_ROAM_QUALITY,
    KEY_ROGUE_AP,
    KEY_STICKY_CLIENT,
    KEY_TX_POWER_LOUD,
    ROGUE_BSS_TYPE,
    AirtimeSaturationDetector,
    BandSteeringDetector,
    ChannelPlanDetector,
    DfsRecurringDetector,
    LegacyRatesDetector,
    MeshUplinkDetector,
    MinRssiMisconfigDetector,
    PingpongRoamerDetector,
    RoamQualityDetector,
    RogueApDetector,
    StickyClientDetector,
    TxPowerLoudDetector,
)
from netadmin.detect.engine import UNKNOWN
from netadmin.domain.entities import Entity
from netadmin.domain.types import EntityType, Severity
from netadmin.store.repository import Repository, SampleReading
from tests.netadmin.detect.support import FakeBaselines

NOW = 4_000_000
DAY = 86_400


# ---------------------------------------------------------------------- #
# Fixture builders
# ---------------------------------------------------------------------- #
def _ctx(repo: Repository, *, settings=None, now: int = NOW) -> DetectorContext:
    return DetectorContext(
        repo=repo, baselines=FakeBaselines(), now_ts=now, site_id="default", settings=settings
    )


def _settings(key: str, **overrides) -> SimpleNamespace:
    return SimpleNamespace(thresholds={key: overrides}, poll=None)


def seed_cov(repo: Repository, *, now: int = NOW, jobs=("fast_device", "fast_sta")) -> None:
    """Full live coverage for the given jobs over the last 600 s (10 polls each)."""
    for job in jobs:
        ts = now - 600 + 60
        while ts <= now:
            repo.record_poll_run(job=job, ok=True, ts=ts)
            ts += 60


def seed_low_cov(repo: Repository, *, now: int = NOW, jobs=("fast_device", "fast_sta")) -> None:
    """Only two polls in the 600 s window -> coverage 0.2 < 0.5 -> UNKNOWN."""
    for job in jobs:
        repo.record_poll_run(job=job, ok=True, ts=now - 120)
        repo.record_poll_run(job=job, ok=True, ts=now - 60)


def mk_ap(
    repo: Repository,
    native_id: str,
    *,
    name: Optional[str] = None,
    meta: Optional[dict] = None,
    uplink_type: Optional[str] = None,
    uplink_hops: Optional[int] = None,
    now: int = NOW,
) -> int:
    eid = repo.upsert_entity(
        Entity(entity_type=EntityType.AP, native_id=native_id, name=name, meta=meta or {}),
        ts=now,
    )
    if uplink_type is not None:
        repo.record_state_change(eid, "uplink_type", uplink_type, ts=now)
    if uplink_hops is not None:
        repo.record_state_change(eid, "uplink_hops", str(uplink_hops), ts=now)
    return eid


def mk_radio(
    repo: Repository,
    native_id: str,
    parent_id: int,
    *,
    band: str,
    ht: Optional[int] = None,
    channel: Optional[int] = None,
    meta_extra: Optional[dict] = None,
    now: int = NOW,
) -> int:
    meta = {"band": band}
    if ht is not None:
        meta["ht"] = ht
    if meta_extra:
        meta.update(meta_extra)
    eid = repo.upsert_entity(
        Entity(entity_type=EntityType.RADIO, native_id=native_id, parent_id=parent_id, meta=meta),
        ts=now,
    )
    if channel is not None:
        repo.record_state_change(eid, "channel", str(channel), ts=now)
    return eid


def mk_client(
    repo: Repository,
    native_id: str,
    *,
    parent_id: Optional[int] = None,
    is_wired: bool = False,
    essid: str = "wifi",
    ap_mac: Optional[str] = None,
    band_history: Optional[list] = None,
    now: int = NOW,
) -> int:
    eid = repo.upsert_entity(
        Entity(
            entity_type=EntityType.CLIENT,
            native_id=native_id,
            parent_id=parent_id,
            meta={"is_wired": is_wired, "essid": essid},
        ),
        ts=now,
    )
    if ap_mac is not None:
        repo.record_state_change(eid, "ap_mac", ap_mac, ts=now)
    if band_history:
        for i, band in enumerate(band_history):
            repo.record_state_change(eid, "band", band, ts=now - (len(band_history) - i) * 100)
    return eid


def gauge(
    repo: Repository,
    entity_id: int,
    metric: str,
    values: list[float],
    *,
    step: int = 60,
    now: int = NOW,
) -> None:
    """Seed gauge samples ending just before ``now`` (all inside a 600 s window)."""
    n = len(values)
    repo.record_samples(
        SampleReading(entity_id, metric, now - (n - i) * step, float(v))
        for i, v in enumerate(values)
    )


def roam(repo: Repository, client_id: int, ts: int, from_ap_id: Optional[int]) -> None:
    repo.record_event(ts=ts, key="EVT_WU_Roam", entity_id=client_id, related_entity_id=from_ap_id)


# ====================================================================== #
# wifi.sticky_client
# ====================================================================== #
def _sticky_client(repo: Repository, native_id: str, ap_mac: str, *, better: bool) -> int:
    cid = mk_client(repo, native_id, ap_mac=ap_mac)
    if better:
        # A prior attachment to a different AP where the client saw a strong signal.
        repo.record_state_change(cid, "ap_mac", "ap-far", ts=NOW - 5000)
        repo.record_state_change(cid, "ap_mac", ap_mac, ts=NOW - 3000)
        repo.record_samples([SampleReading(cid, "rssi", NOW - 4800, -58.0)])
    gauge(repo, cid, "rssi", [-82.0] * 8)
    gauge(repo, cid, "tx_rate", [12.0] * 8)
    return cid


def test_sticky_client_fires_with_better_ap(repo: Repository) -> None:
    seed_cov(repo)
    _sticky_client(repo, "cli-1", "ap-near", better=True)

    findings = StickyClientDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_STICKY_CLIENT
    assert f.severity is Severity.P3
    assert "better_ap_exists" in f.confounders_checked
    assert f.evidence["better_ap"] == "ap-far"


def test_sticky_client_suppressed_without_better_ap(repo: Repository) -> None:
    seed_cov(repo)
    # Sustained weak RSSI but no historically-better AP -> coverage hole, not sticky.
    _sticky_client(repo, "cli-1", "ap-near", better=False)
    assert StickyClientDetector().evaluate(_ctx(repo)) == []


def test_sticky_client_clustered_is_p2(repo: Repository) -> None:
    seed_cov(repo)
    for i in range(3):
        _sticky_client(repo, f"cli-{i}", "ap-near", better=True)
    findings = StickyClientDetector().evaluate(_ctx(repo))
    assert len(findings) == 3
    assert all(f.severity is Severity.P2 for f in findings)
    assert all(f.evidence["clustered_on_ap"] for f in findings)


def test_sticky_client_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    _sticky_client(repo, "cli-1", "ap-near", better=True)
    assert StickyClientDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.pingpong_roamer
# ====================================================================== #
def test_pingpong_fires_on_meraki_burst(repo: Repository) -> None:
    seed_cov(repo)
    ap_a = mk_ap(repo, "ap-a")
    ap_b = mk_ap(repo, "ap-b")
    cid = mk_client(repo, "cli-1")
    for i, ts in enumerate((NOW - 40, NOW - 30, NOW - 20, NOW - 10, NOW - 1)):
        roam(repo, cid, ts, ap_a if i % 2 == 0 else ap_b)

    findings = PingpongRoamerDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.P2
    assert f.evidence["reason"] == "meraki_burst"
    assert f.evidence["distinct_aps"] == 2
    assert "two_ap_bounce_not_walk" in f.confounders_checked


def test_pingpong_fires_on_definite_rate(repo: Repository) -> None:
    seed_cov(repo)
    ap_a = mk_ap(repo, "ap-a")
    ap_b = mk_ap(repo, "ap-b")
    cid = mk_client(repo, "cli-1")
    # 15 roams spaced 100 s apart (no burst) -> rate 15/h >= definite (12/h).
    for i in range(15):
        roam(repo, cid, NOW - 3500 + i * 100, ap_a if i % 2 == 0 else ap_b)

    findings = PingpongRoamerDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["reason"] == "rate_definite"


def test_pingpong_suppressed_for_walk_through(repo: Repository) -> None:
    seed_cov(repo)
    aps = [mk_ap(repo, f"ap-{i}") for i in range(3)]
    cid = mk_client(repo, "cli-1")
    # Three roams across three distinct APs, spaced 20 s: not a 2-AP bounce, low rate.
    for i, ap in enumerate(aps):
        roam(repo, cid, NOW - 200 + i * 20, ap)
    assert PingpongRoamerDetector().evaluate(_ctx(repo)) == []


def test_pingpong_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap_a = mk_ap(repo, "ap-a")
    cid = mk_client(repo, "cli-1")
    for ts in (NOW - 40, NOW - 30, NOW - 20, NOW - 10):
        roam(repo, cid, ts, ap_a)
    assert PingpongRoamerDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.roam_quality
# ====================================================================== #
def _roam_pair(repo: Repository, cid: int, roam_ts: int, before: float, after: float) -> None:
    repo.record_samples(
        [
            SampleReading(cid, "rssi", roam_ts - 60, before),
            SampleReading(cid, "rssi", roam_ts - 30, before),
            SampleReading(cid, "rssi", roam_ts + 30, after),
            SampleReading(cid, "rssi", roam_ts + 60, after),
        ]
    )
    roam(repo, cid, roam_ts, None)


def test_roam_quality_fires_on_bad_roams(repo: Repository) -> None:
    seed_cov(repo)
    cid = mk_client(repo, "cli-1")
    _roam_pair(repo, cid, NOW - 1000, before=-55.0, after=-75.0)
    _roam_pair(repo, cid, NOW - 500, before=-55.0, after=-75.0)

    findings = RoamQualityDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_ROAM_QUALITY
    assert f.severity is Severity.P3
    assert f.evidence["bad_roams"] == 2
    assert "transient_dip_excluded" in f.confounders_checked


def test_roam_quality_suppressed_when_signal_holds(repo: Repository) -> None:
    seed_cov(repo)
    cid = mk_client(repo, "cli-1")
    _roam_pair(repo, cid, NOW - 1000, before=-55.0, after=-56.0)
    _roam_pair(repo, cid, NOW - 500, before=-55.0, after=-57.0)
    assert RoamQualityDetector().evaluate(_ctx(repo)) == []


def test_roam_quality_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    cid = mk_client(repo, "cli-1")
    _roam_pair(repo, cid, NOW - 1000, before=-55.0, after=-75.0)
    _roam_pair(repo, cid, NOW - 500, before=-55.0, after=-75.0)
    assert RoamQualityDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.min_rssi_misconfig
# ====================================================================== #
def test_min_rssi_fires_stricter_than_floor(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")  # multi-AP site, not mesh
    mk_radio(
        repo, "ap-1:na", ap1, band="na", meta_extra={"min_rssi_enabled": True, "min_rssi": -65}
    )

    findings = MinRssiMisconfigDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.P3
    assert f.evidence["reason"] == "stricter_than_floor"


def test_min_rssi_fires_p2_on_mesh_ap(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1", meta={"mesh_enabled": True})
    mk_ap(repo, "ap-2")
    mk_radio(
        repo, "ap-1:na", ap1, band="na", meta_extra={"min_rssi_enabled": True, "min_rssi": -80}
    )

    findings = MinRssiMisconfigDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["reason"] == "mesh_uplink_ap"


def test_min_rssi_fires_p2_on_single_ap_site(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(
        repo, "ap-1:na", ap1, band="na", meta_extra={"min_rssi_enabled": True, "min_rssi": -80}
    )

    findings = MinRssiMisconfigDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["reason"] == "single_ap_site"


def test_min_rssi_suppressed_when_safe(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")  # multi-AP, roam targets exist
    # Enabled but lenient (-80), not mesh, not single-AP -> no misconfig.
    mk_radio(
        repo, "ap-1:na", ap1, band="na", meta_extra={"min_rssi_enabled": True, "min_rssi": -80}
    )
    assert MinRssiMisconfigDetector().evaluate(_ctx(repo)) == []


def test_min_rssi_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(
        repo, "ap-1:na", ap1, band="na", meta_extra={"min_rssi_enabled": True, "min_rssi": -65}
    )
    assert MinRssiMisconfigDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.channel_plan
# ====================================================================== #
def test_channel_plan_fires_off_grid_24(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:ng", ap1, band="ng", ht=20, channel=3)  # off 1/6/11

    findings = ChannelPlanDetector().evaluate(_ctx(repo))
    subtypes = {f.dims["subtype"] for f in findings}
    assert "channel_off_grid" in subtypes
    assert all(f.severity is Severity.P3 for f in findings)


def test_channel_plan_fires_co_channel_reuse(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    ap2 = mk_ap(repo, "ap-2")
    mk_radio(repo, "ap-1:na", ap1, band="na", ht=40, channel=36)
    mk_radio(repo, "ap-2:na", ap2, band="na", ht=40, channel=36)  # same channel

    findings = ChannelPlanDetector().evaluate(_ctx(repo))
    assert any(f.dims["subtype"] == "co_channel_reuse" for f in findings)


def test_channel_plan_suppressed_when_clean(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:ng", ap1, band="ng", ht=20, channel=6)  # on-grid, 20 MHz
    mk_radio(repo, "ap-1:na", ap1, band="na", ht=40, channel=36)  # 40 MHz on 5 GHz is fine
    assert ChannelPlanDetector().evaluate(_ctx(repo)) == []


def test_channel_plan_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:ng", ap1, band="ng", ht=20, channel=3)
    assert ChannelPlanDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.dfs_recurring
# ====================================================================== #
def _radar(repo: Repository, ap_id: int, ts: int) -> None:
    repo.record_event(ts=ts, key="EVT_AP_RadarDetected", entity_id=ap_id)


def test_dfs_fires_on_recurring_radar(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    # 7 hits within the last 7 days, at distinct hours-of-day (no clustering).
    for j in range(1, 8):
        _radar(repo, ap1, NOW - j * DAY + j * 3600)

    findings = DfsRecurringDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_DFS_RECURRING
    assert f.severity is Severity.P3
    assert f.evidence["radar_events"] == 7
    assert "recurrence_over_days" in f.confounders_checked


def test_dfs_fires_p2_on_same_hour_clustering(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    # Seven hits, all at the same hour-of-day -> predictable radar -> P2.
    base_hour = (NOW % DAY) - (NOW % 3600)
    for j in range(1, 8):
        _radar(repo, ap1, NOW - j * DAY - (NOW % 3600) + 1800)
    assert base_hour or True  # readability anchor
    findings = DfsRecurringDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert "same_hour_clustering" in findings[0].confounders_checked


def test_dfs_suppressed_on_single_hit(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    _radar(repo, ap1, NOW - 2 * DAY)  # one-off, well under 1/day
    assert DfsRecurringDetector().evaluate(_ctx(repo)) == []


def test_dfs_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    for j in range(1, 9):
        _radar(repo, ap1, NOW - j * DAY)
    assert DfsRecurringDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.airtime_saturation
# ====================================================================== #
def test_airtime_fires_critical(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    rid = mk_radio(repo, "ap-1:na", ap1, band="na")
    gauge(repo, rid, "cu_total", [85.0] * 8)
    gauge(repo, rid, "cu_self_rx", [10.0] * 8)
    gauge(repo, rid, "cu_self_tx", [10.0] * 8)

    findings = AirtimeSaturationDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_AIRTIME_SATURATION
    assert f.severity is Severity.P1
    assert f.evidence["level"] == "critical"
    assert f.evidence["dominant_source"] == "non_self"
    assert "self_vs_non_self_split" in f.confounders_checked


def test_airtime_fires_degraded_p2(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    rid = mk_radio(repo, "ap-1:na", ap1, band="na")
    gauge(repo, rid, "cu_total", [60.0] * 8)

    findings = AirtimeSaturationDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["level"] == "degraded"


def test_airtime_suppressed_on_burst(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    rid = mk_radio(repo, "ap-1:na", ap1, band="na")
    # Mostly quiet with a single spike -> not sustained.
    gauge(repo, rid, "cu_total", [20.0, 20.0, 20.0, 90.0, 20.0, 20.0, 20.0, 20.0])
    assert AirtimeSaturationDetector().evaluate(_ctx(repo)) == []


def test_airtime_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    rid = mk_radio(repo, "ap-1:na", ap1, band="na")
    gauge(repo, rid, "cu_total", [85.0] * 8)
    assert AirtimeSaturationDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.tx_power_loud
# ====================================================================== #
def test_tx_power_fires_p3_multi_ap_high(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")
    mk_radio(repo, "ap-1:na", ap1, band="na", meta_extra={"tx_power_mode": "high"})

    findings = TxPowerLoudDetector().evaluate(_ctx(repo))
    loud = [f for f in findings if f.dims.get("subtype") == "loud_power"]
    assert len(loud) == 1
    assert loud[0].severity is Severity.P3
    assert "multi_ap_site" in loud[0].confounders_checked


def test_tx_power_escalates_p2_with_sticky_cluster(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")
    mk_radio(repo, "ap-1:na", ap1, band="na", meta_extra={"tx_power_mode": "high"})
    # Three weak clients parked on ap-1 -> sticky concentration corroborates.
    for i in range(3):
        c = mk_client(repo, f"cli-{i}", parent_id=ap1, ap_mac="ap-1")
        gauge(repo, c, "rssi", [-78.0] * 8)

    findings = TxPowerLoudDetector().evaluate(_ctx(repo))
    loud = [f for f in findings if f.dims.get("subtype") == "loud_power"]
    assert loud and loud[0].severity is Severity.P2
    assert loud[0].evidence["sticky_clients_on_ap"] == 3


def test_tx_power_imbalance_subcase(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")
    mk_radio(repo, "ap-1:ng", ap1, band="ng", meta_extra={"tx_power": 20})
    mk_radio(repo, "ap-1:na", ap1, band="na", meta_extra={"tx_power": 20})  # 2.4 not below 5

    findings = TxPowerLoudDetector().evaluate(_ctx(repo))
    assert any(f.dims.get("subtype") == "band_imbalance" for f in findings)


def test_tx_power_suppressed_single_ap(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:na", ap1, band="na", meta_extra={"tx_power_mode": "high"})
    assert TxPowerLoudDetector().evaluate(_ctx(repo)) == []


def test_tx_power_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_ap(repo, "ap-2")
    mk_radio(repo, "ap-1:na", ap1, band="na", meta_extra={"tx_power_mode": "high"})
    assert TxPowerLoudDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.legacy_rates
# ====================================================================== #
def test_legacy_rates_fires_on_11b_client(repo: Repository) -> None:
    seed_cov(repo)
    cid = mk_client(repo, "cli-1")
    gauge(repo, cid, "tx_rate", [11.0] * 8)

    findings = LegacyRatesDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_LEGACY_RATES
    assert f.severity is Severity.P3
    assert f.evidence["matches_11b_rate"] is True
    assert "rate_sustained_not_momentary" in f.confounders_checked


def test_legacy_rates_suppressed_for_fast_client(repo: Repository) -> None:
    seed_cov(repo)
    cid = mk_client(repo, "cli-1")
    gauge(repo, cid, "tx_rate", [300.0] * 8)
    assert LegacyRatesDetector().evaluate(_ctx(repo)) == []


def test_legacy_rates_excludes_wired(repo: Repository) -> None:
    seed_cov(repo)
    cid = mk_client(repo, "cli-1", is_wired=True)
    gauge(repo, cid, "tx_rate", [11.0] * 8)
    assert LegacyRatesDetector().evaluate(_ctx(repo)) == []


def test_legacy_rates_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    cid = mk_client(repo, "cli-1")
    gauge(repo, cid, "tx_rate", [11.0] * 8)
    assert LegacyRatesDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.band_steering
# ====================================================================== #
def test_band_steering_fires_steer_up(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:na", ap1, band="na")  # idle 5 GHz radio, no cu samples
    cid = mk_client(repo, "cli-1", parent_id=ap1, band_history=["na", "ng"])
    gauge(repo, cid, "rssi", [-60.0] * 8)  # strong 2.4

    findings = BandSteeringDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.dims["subtype"] == "parked_on_24"
    assert f.severity is Severity.P3
    assert "dual_band_confirmed" in f.confounders_checked


def test_band_steering_fires_steer_down(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    cid = mk_client(repo, "cli-1", parent_id=ap1, band_history=["na"])
    gauge(repo, cid, "rssi", [-85.0] * 8)  # held on 5 GHz, too weak

    findings = BandSteeringDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].dims["subtype"] == "held_on_5"
    assert "weak_rssi_sustained" in findings[0].confounders_checked


def test_band_steering_suppressed_single_band(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:na", ap1, band="na")  # idle 5 GHz available
    # Strong on 2.4 but never seen on 5 GHz -> cannot prove dual-band -> no nag.
    cid = mk_client(repo, "cli-1", parent_id=ap1, band_history=["ng"])
    gauge(repo, cid, "rssi", [-60.0] * 8)
    assert BandSteeringDetector().evaluate(_ctx(repo)) == []


def test_band_steering_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:na", ap1, band="na")
    cid = mk_client(repo, "cli-1", parent_id=ap1, band_history=["na", "ng"])
    gauge(repo, cid, "rssi", [-60.0] * 8)
    assert BandSteeringDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# wifi.mesh_uplink
# ====================================================================== #
def test_mesh_uplink_fires_on_bad_rssi(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1", uplink_type="wireless")
    gauge(repo, ap1, "uplink_rssi", [-75.0] * 8)

    findings = MeshUplinkDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_MESH_UPLINK
    assert f.severity is Severity.P2
    assert "sustained_poor_rssi" in f.confounders_checked


def test_mesh_uplink_warn_escalates_with_reconnects(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1", uplink_type="wireless")
    gauge(repo, ap1, "uplink_rssi", [-67.0] * 8)  # in warn band (-65..-70)
    for ts in (NOW - 400, NOW - 200):
        repo.record_event(ts=ts, key="EVT_AP_Lost_Contact", entity_id=ap1)

    findings = MeshUplinkDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["reconnect_cycles"] == 2
    assert "reconnect_corroboration_checked" in findings[0].confounders_checked


def test_mesh_uplink_warn_only_is_p3(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1", uplink_type="wireless", uplink_hops=1)
    gauge(repo, ap1, "uplink_rssi", [-67.0] * 8)  # warn band, no corroboration
    findings = MeshUplinkDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P3


def test_mesh_uplink_latent_wired_with_mesh_enabled(repo: Repository) -> None:
    seed_cov(repo)
    mk_ap(repo, "ap-1", uplink_type="wire", meta={"mesh_enabled": True})
    findings = MeshUplinkDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].dims["subtype"] == "wired_with_mesh_enabled"
    assert findings[0].severity is Severity.P3


def test_mesh_uplink_suppressed_on_strong_uplink(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1", uplink_type="wireless")
    gauge(repo, ap1, "uplink_rssi", [-55.0] * 8)  # healthy backhaul
    assert MeshUplinkDetector().evaluate(_ctx(repo)) == []


def test_mesh_uplink_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    ap1 = mk_ap(repo, "ap-1", uplink_type="wireless")
    gauge(repo, ap1, "uplink_rssi", [-75.0] * 8)
    assert MeshUplinkDetector().evaluate(_ctx(repo)) is UNKNOWN


# ====================================================================== #
# threshold override wiring (spot-check the settings seam)
# ====================================================================== #
def test_airtime_threshold_override(repo: Repository) -> None:
    seed_cov(repo)
    ap1 = mk_ap(repo, "ap-1")
    rid = mk_radio(repo, "ap-1:na", ap1, band="na")
    gauge(repo, rid, "cu_total", [40.0] * 8)
    # Default degraded is 50%; lower it to 30% so 40% now fires.
    settings = _settings(KEY_AIRTIME_SATURATION, degraded_pct=30)
    findings = AirtimeSaturationDetector().evaluate(_ctx(repo, settings=settings))
    assert len(findings) == 1
    assert findings[0].evidence["level"] == "degraded"


def test_pingpong_threshold_override(repo: Repository) -> None:
    seed_cov(repo)
    ap_a = mk_ap(repo, "ap-a")
    ap_b = mk_ap(repo, "ap-b")
    cid = mk_client(repo, "cli-1")
    for i in range(4):
        roam(repo, cid, NOW - 300 + i * 60, ap_a if i % 2 == 0 else ap_b)
    # 4 roams/h: below default suspicious (5) but a lowered tier catches it.
    settings = _settings(KEY_PINGPONG_ROAMER, suspicious_rate_per_h=3)
    findings = PingpongRoamerDetector().evaluate(_ctx(repo, settings=settings))
    assert len(findings) == 1
    assert findings[0].evidence["reason"] == "rate_suspicious"
    assert findings[0].severity is Severity.P3


# ====================================================================== #
# wifi.rogue_ap
# ====================================================================== #
def mk_rogue(
    repo: Repository,
    bssid: str,
    *,
    channel: int,
    rssi: int,
    band: Optional[str] = None,
    essid: str = "Neighbor",
    first_seen: Optional[int] = None,
    last_seen: int = NOW,
    is_rogue: bool = True,
    is_ubnt: Optional[bool] = None,
    scan_ts: Optional[list] = None,
    seen_by_ap: str = "ap-1",
) -> int:
    """Seed a ``rogue_bss`` inventory entity as the daily rogueap poll would.

    ``first_seen``/``last_seen`` control the sighting span the detector reads for
    its (legacy) span-based persistence fallback; ``scan_ts`` supplies the
    per-scan sighting log the detector now prefers. ``is_ubnt`` mirrors the
    controller's own-hardware flag.
    """
    meta: dict = {"channel": channel, "rssi": rssi, "is_rogue": is_rogue, "seen_by_ap": seen_by_ap}
    if band is not None:
        meta["band"] = band
    if is_ubnt is not None:
        meta["is_ubnt"] = is_ubnt
    if scan_ts is not None:
        meta["scan_ts"] = scan_ts
    return repo.upsert_entity(
        Entity(
            entity_type=ROGUE_BSS_TYPE,  # type: ignore[arg-type]
            native_id=bssid,
            name=essid,
            meta=meta,
            first_seen_ts=first_seen if first_seen is not None else last_seen,
        ),
        ts=last_seen,
    )


def _our_5ghz_radio(repo: Repository, *, channel: int = 36) -> int:
    ap = mk_ap(repo, "ap-1")
    return mk_radio(repo, "ap-1:na", ap, band="na", ht=20, channel=channel)


def test_rogue_ap_fires_on_strong_persistent_same_channel(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    mk_rogue(repo, "de:ad:be:ef:00:01", channel=36, rssi=-60, band="na", first_seen=NOW - 2 * DAY)

    findings = RogueApDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_key == KEY_ROGUE_AP
    assert f.severity is Severity.P3
    assert f.entity.native_id == "de:ad:be:ef:00:01"
    assert f.evidence["channel"] == 36
    assert f.evidence["overlapping_radios"] == ["ap-1:na"]
    assert f.evidence["materially_congested"] is False
    assert "own_radio_channel_overlap" in f.confounders_checked


def test_rogue_ap_p2_when_overlapping_congested_radio(repo: Repository) -> None:
    seed_cov(repo)
    radio = _our_5ghz_radio(repo, channel=36)
    gauge(repo, radio, "cu_total", [72.0] * 8)  # sustained congestion on the overlapped radio
    mk_rogue(repo, "de:ad:be:ef:00:02", channel=36, rssi=-58, band="na", first_seen=NOW - 2 * DAY)

    findings = RogueApDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.P2
    assert findings[0].evidence["materially_congested"] is True
    assert findings[0].evidence["congested_overlap_radios"] == ["ap-1:na"]
    assert "overlapped_radio_congestion_checked" in findings[0].confounders_checked


def test_rogue_ap_fires_on_24ghz_adjacent_overlap(repo: Repository) -> None:
    seed_cov(repo)
    ap = mk_ap(repo, "ap-1")
    mk_radio(repo, "ap-1:ng", ap, band="ng", ht=20, channel=6)
    # Channel 8 is 2 away from our channel 6 -> within the 2.4 GHz overlap distance.
    mk_rogue(repo, "de:ad:be:ef:00:03", channel=8, rssi=-64, band="ng", first_seen=NOW - 2 * DAY)

    findings = RogueApDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].evidence["channel"] == 8


def test_rogue_ap_suppressed_for_single_scan(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Seen in exactly one scan (span 0) -> transient, not yet a rogue.
    mk_rogue(repo, "de:ad:be:ef:00:04", channel=36, rssi=-55, band="na", first_seen=NOW)
    assert RogueApDetector().evaluate(_ctx(repo)) == []


def test_rogue_ap_suppressed_for_weak_neighbor(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Persistent and co-channel but weak (below the -75 dBm floor) -> advisory only.
    mk_rogue(repo, "de:ad:be:ef:00:05", channel=36, rssi=-85, band="na", first_seen=NOW - 2 * DAY)
    assert RogueApDetector().evaluate(_ctx(repo)) == []


def test_rogue_ap_suppressed_for_allowlisted_bssid(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    mk_rogue(repo, "de:ad:be:ef:00:06", channel=36, rssi=-55, band="na", first_seen=NOW - 2 * DAY)
    settings = _settings(KEY_ROGUE_AP, known_bssids=["DE:AD:BE:EF:00:06"])  # our own hardware
    assert RogueApDetector().evaluate(_ctx(repo, settings=settings)) == []


def test_rogue_ap_suppressed_for_own_ubnt_hardware(repo: Repository) -> None:
    """Our own AP's virtual BSSID, seen in a neighbor scan, is never a rogue.

    The neighbor BSS is Ubiquiti (``is_ubnt``) and shares our managed AP's
    vendor+device MAC prefix (only the low octet differs, as UniFi virtual BSSIDs
    do) -> auto-excluded even with an empty allowlist.
    """
    seed_cov(repo)
    ap = mk_ap(repo, "f0:9f:c2:11:22:33")  # a managed AP, MAC as native_id
    mk_radio(repo, "f0:9f:c2:11:22:33:na", ap, band="na", ht=20, channel=36)
    # Same first five octets as our AP, low octet differs -> our own virtual BSSID.
    mk_rogue(
        repo,
        "f0:9f:c2:11:22:44",
        channel=36,
        rssi=-55,
        band="na",
        is_ubnt=True,
        first_seen=NOW - 2 * DAY,
    )
    assert RogueApDetector().evaluate(_ctx(repo)) == []


def test_rogue_ap_real_ubnt_neighbor_still_fires(repo: Repository) -> None:
    """A neighbor's *own* Ubiquiti gear (different device prefix) is a real rogue."""
    seed_cov(repo)
    ap = mk_ap(repo, "f0:9f:c2:11:22:33")
    mk_radio(repo, "f0:9f:c2:11:22:33:na", ap, band="na", ht=20, channel=36)
    # Ubiquiti, but a completely different device prefix -> not ours.
    mk_rogue(
        repo,
        "aa:bb:cc:dd:ee:ff",
        channel=36,
        rssi=-55,
        band="na",
        is_ubnt=True,
        first_seen=NOW - 2 * DAY,
    )
    findings = RogueApDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].evidence["controller_is_ubnt"] is True


def test_rogue_ap_persistence_uses_distinct_recent_scans(repo: Repository) -> None:
    """A BSS seen once long ago and again today (huge span, absent the interim)
    is not persistent; a BSS seen in several recent scans is."""
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Span ~90 days would pass the old rule, but only ONE scan falls in the recency
    # window (today) -> not persistent.
    mk_rogue(
        repo,
        "de:ad:be:ef:00:20",
        channel=36,
        rssi=-55,
        band="na",
        first_seen=NOW - 90 * DAY,
        scan_ts=[NOW - 90 * DAY, NOW],
    )
    assert RogueApDetector().evaluate(_ctx(repo)) == []

    # Seen across three recent daily scans -> genuinely persistent.
    mk_rogue(
        repo,
        "de:ad:be:ef:00:21",
        channel=36,
        rssi=-55,
        band="na",
        scan_ts=[NOW - 2 * 3600, NOW - 3600, NOW],
    )
    findings = RogueApDetector().evaluate(_ctx(repo))
    assert [f.entity.native_id for f in findings] == ["de:ad:be:ef:00:21"]
    assert findings[0].evidence["logged_scan_count"] == 3


def test_rogue_ap_suppressed_when_not_on_our_channel(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Strong and persistent, but on channel 149 -> no overlap with our channel 36.
    mk_rogue(repo, "de:ad:be:ef:00:07", channel=149, rssi=-55, band="na", first_seen=NOW - 2 * DAY)
    assert RogueApDetector().evaluate(_ctx(repo)) == []


def test_rogue_ap_suppressed_for_stale_sighting(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Last seen 5 days ago -> beyond the recency window -> the neighbor is gone.
    mk_rogue(
        repo,
        "de:ad:be:ef:00:08",
        channel=36,
        rssi=-55,
        band="na",
        first_seen=NOW - 7 * DAY,
        last_seen=NOW - 5 * DAY,
    )
    assert RogueApDetector().evaluate(_ctx(repo)) == []


def test_rogue_ap_unknown_on_no_data(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # No rogue_bss rows at all: a fresh/unscanned store is not a clean clear.
    assert RogueApDetector().evaluate(_ctx(repo)) is UNKNOWN


def test_rogue_ap_unknown_on_low_coverage(repo: Repository) -> None:
    seed_low_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    mk_rogue(repo, "de:ad:be:ef:00:09", channel=36, rssi=-55, band="na", first_seen=NOW - 2 * DAY)
    assert RogueApDetector().evaluate(_ctx(repo)) is UNKNOWN


def test_rogue_ap_infers_band_from_channel(repo: Repository) -> None:
    seed_cov(repo)
    _our_5ghz_radio(repo, channel=36)
    # Band field absent from the scan row -> inferred from channel 36 (-> 5 GHz).
    mk_rogue(repo, "de:ad:be:ef:00:0a", channel=36, rssi=-60, band=None, first_seen=NOW - 2 * DAY)
    findings = RogueApDetector().evaluate(_ctx(repo))
    assert len(findings) == 1
    assert findings[0].evidence["band"] == "5"
