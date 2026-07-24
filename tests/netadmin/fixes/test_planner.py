"""Planner: correct payloads for the safe templates, advisories for the rest.

Every assertion is on the *rendered payload* the planner produced -- the exact body
a dry-run would show and a confirmed apply would send -- never on a network effect.
"""

from __future__ import annotations

from netadmin.domain.types import EntityType, Severity
from netadmin.fixes.models import ActionType
from netadmin.fixes.planner import plan_fix

from .conftest import (
    AP_ID,
    AP_MAC,
    SW_MAC,
    make_ap_device,
    make_finding,
    make_switch_device,
    port_entity,
    radio_entity,
)


def _radio(payload, band):
    return next(r for r in payload["radio_table"] if r["radio"] == band)


# --------------------------------------------------------------------------- #
# min-RSSI removal -- removal only, ever
# --------------------------------------------------------------------------- #
def test_min_rssi_plan_only_disables_and_preserves_other_radios(ap_device):
    finding = make_finding(
        "wifi.min_rssi_misconfig",
        radio_entity("ng"),
        severity=Severity.P2,
        evidence={"min_rssi_dbm": -75, "reason": "mesh_uplink_ap", "on_mesh_ap": True},
    )
    plan = plan_fix(finding, device=ap_device)

    assert not plan.is_advisory
    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.action is ActionType.MIN_RSSI_REMOVE
    assert step.method == "PUT"
    assert step.endpoint == f"rest/device/{AP_ID}"
    # The target radio is disabled; the min_rssi floor value is preserved (removal
    # is a disable, not a rewrite), and the *other* radio is untouched.
    ng = _radio(step.payload, "ng")
    assert ng["min_rssi_enabled"] is False
    assert ng["min_rssi"] == -75
    assert _radio(step.payload, "na")["min_rssi_enabled"] is False
    # Precondition: it must still be enabled to be worth removing.
    assert step.precondition.expected == {"min_rssi_enabled": True}
    assert step.precondition.target_native_id == f"{AP_MAC}:ng"
    # Revert restores the original (enabled) table.
    assert step.revertible is True
    assert _radio(step.before["body"], "ng")["min_rssi_enabled"] is True


def test_min_rssi_plan_is_advisory_when_already_disabled():
    device = make_ap_device(radios=[{"radio": "ng", "min_rssi_enabled": False, "min_rssi": 0}])
    finding = make_finding("wifi.min_rssi_misconfig", radio_entity("ng"))
    plan = plan_fix(finding, device=device)
    assert plan.is_advisory
    assert plan.manual_action_required


def test_min_rssi_plan_never_emits_a_set_even_for_strict_floor(ap_device):
    # The stricter-than-floor sub-case is still handled by *removal*, never by
    # writing a looser floor -- the planner has no code path that enables min-RSSI.
    finding = make_finding(
        "wifi.min_rssi_misconfig",
        radio_entity("ng"),
        evidence={"reason": "stricter_than_floor", "min_rssi_dbm": -60, "on_mesh_ap": False},
    )
    plan = plan_fix(finding, device=ap_device)
    assert plan.steps[0].payload["radio_table"][0]["min_rssi_enabled"] is False


# --------------------------------------------------------------------------- #
# channel change -- 2.4 GHz grid only
# --------------------------------------------------------------------------- #
def test_channel_off_grid_snaps_to_nearest_valid_channel(ap_device):
    finding = make_finding(
        "wifi.channel_plan",
        radio_entity("ng"),
        dims={"subtype": "channel_off_grid", "band": "2.4"},
        evidence={"subtype": "channel_off_grid", "band": "2.4", "channel": 3},
    )
    plan = plan_fix(finding, device=ap_device)
    step = plan.steps[0]
    assert step.action is ActionType.CHANNEL_CHANGE
    assert _radio(step.payload, "ng")["channel"] == 1  # nearest of 1/6/11 to 3
    assert step.precondition.expected == {"channel": 3}


def test_co_channel_reuse_rotates_onto_next_grid_slot(ap_device):
    device = make_ap_device(radios=[{"radio": "ng", "channel": 6, "ht": 20}])
    finding = make_finding(
        "wifi.channel_plan",
        radio_entity("ng"),
        dims={"subtype": "co_channel_reuse", "band": "2.4"},
        evidence={"subtype": "co_channel_reuse", "band": "2.4", "channel": 6},
    )
    plan = plan_fix(finding, device=device)
    assert _radio(plan.steps[0].payload, "ng")["channel"] == 11


def test_five_ghz_channel_case_is_advisory(ap_device):
    finding = make_finding(
        "wifi.channel_plan",
        radio_entity("na"),
        dims={"subtype": "co_channel_reuse", "band": "5"},
        evidence={"subtype": "co_channel_reuse", "band": "5", "channel": 36},
    )
    plan = plan_fix(finding, device=ap_device)
    assert plan.is_advisory
    assert plan.manual_action_required


def test_wide_channel_subtype_is_advisory(ap_device):
    finding = make_finding(
        "wifi.channel_plan",
        radio_entity("ng"),
        dims={"subtype": "wide_channel_24ghz", "band": "2.4"},
        evidence={"subtype": "wide_channel_24ghz", "band": "2.4", "channel": 6, "ht_mhz": 40},
    )
    plan = plan_fix(finding, device=ap_device)
    assert plan.is_advisory


# --------------------------------------------------------------------------- #
# tx-power step-down
# --------------------------------------------------------------------------- #
def test_tx_power_high_steps_to_medium(ap_device):
    finding = make_finding(
        "wifi.tx_power_loud",
        radio_entity("ng"),
        dims={"subtype": "loud_power", "band": "2.4"},
        evidence={"tx_power_mode": "high"},
    )
    plan = plan_fix(finding, device=ap_device)
    step = plan.steps[0]
    assert step.action is ActionType.TX_POWER_STEP_DOWN
    assert _radio(step.payload, "ng")["tx_power_mode"] == "medium"
    assert step.precondition.expected == {"tx_power_mode": "high"}


def test_tx_power_auto_steps_to_medium():
    device = make_ap_device(radios=[{"radio": "na", "channel": 36, "tx_power_mode": "auto"}])
    finding = make_finding(
        "wifi.tx_power_loud",
        radio_entity("na"),
        evidence={"tx_power_mode": "auto"},
    )
    plan = plan_fix(finding, device=device)
    assert _radio(plan.steps[0].payload, "na")["tx_power_mode"] == "medium"


def test_tx_power_already_low_is_advisory():
    device = make_ap_device(radios=[{"radio": "ng", "channel": 6, "tx_power_mode": "low"}])
    finding = make_finding(
        "wifi.tx_power_loud", radio_entity("ng"), evidence={"tx_power_mode": "low"}
    )
    plan = plan_fix(finding, device=device)
    assert plan.is_advisory


# --------------------------------------------------------------------------- #
# PoE power-cycle -- reboot loop / fault only
# --------------------------------------------------------------------------- #
def test_poe_cycle_planned_for_reboot_loop(switch_device):
    finding = make_finding(
        "wired.port_flapping",
        port_entity(5),
        severity=Severity.P1,
        evidence={"poe_reboot_loop": True, "poe_min_w": 0.0, "poe_max_w": 6.5},
    )
    plan = plan_fix(finding, device=switch_device)
    step = plan.steps[0]
    assert step.action is ActionType.POE_POWER_CYCLE
    assert step.method == "POST"
    assert step.endpoint == "cmd/devmgr"
    assert step.payload == {"cmd": "power-cycle", "mac": SW_MAC, "port_idx": 5}
    assert step.revertible is False  # a transient command, nothing to restore
    assert step.before is None


def test_port_flapping_without_reboot_loop_is_advisory(switch_device):
    finding = make_finding(
        "wired.port_flapping",
        port_entity(5),
        evidence={"transitions_short": 7},  # no PoE reboot signal -> physical
    )
    plan = plan_fix(finding, device=switch_device)
    assert plan.is_advisory
    assert plan.manual_action_required
    assert "physical" in (plan.advisory or "").lower()


# --------------------------------------------------------------------------- #
# Physical-issue refusals + unknown detector
# --------------------------------------------------------------------------- #
def test_physical_issues_return_advisory_with_empty_steps():
    for key in ("wired.bad_cable", "wifi.mesh_uplink", "net.coverage_hole"):
        entity = radio_entity("ng") if key.startswith("wifi") else port_entity(1)
        plan = plan_fix(make_finding(key, entity))
        assert plan.steps == []
        assert plan.manual_action_required
        assert plan.advisory


def test_unknown_detector_returns_advisory():
    plan = plan_fix(make_finding("wifi.some_new_thing", radio_entity("ng")))
    assert plan.is_advisory
    assert plan.manual_action_required


def test_missing_device_snapshot_is_advisory_not_a_guess():
    finding = make_finding(
        "wifi.channel_plan",
        radio_entity("ng"),
        dims={"subtype": "channel_off_grid", "band": "2.4"},
        evidence={"subtype": "channel_off_grid", "band": "2.4", "channel": 3},
    )
    plan = plan_fix(finding, device=None)
    assert plan.is_advisory


def test_device_count_collapses_radios_to_one_device(ap_device):
    finding = make_finding(
        "wifi.tx_power_loud", radio_entity("ng"), evidence={"tx_power_mode": "high"}
    )
    plan = plan_fix(finding, device=ap_device)
    assert plan.device_count == 1
    assert plan.steps[0].target_entity_type is EntityType.RADIO
