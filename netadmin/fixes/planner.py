"""The fix planner (``docs/ARCHITECTURE.md`` section 9).

Pure, I/O-free mapping from a detector finding to a :class:`FixPlan`. Given a
:class:`~netadmin.domain.entities.Finding` and (for config changes) a read-only
snapshot of the target device -- the raw controller device object collected on the
tech-visit/GET path -- it renders concrete, revertible steps whose payloads
preserve every existing field of the object being changed (the UniFi
``rest/device`` PUT replaces the whole ``radio_table``, so a partial body would
wipe untouched radios; the old ``core/change_applier.py`` learned this the hard
way and we keep the discipline).

It plans only the safe, high-value templates:

* ``wifi.channel_plan``   -> a 2.4 GHz channel move onto the 1/6/11 grid.
* ``wifi.tx_power_loud``  -> one power step down (high->medium->low, auto->medium).
* ``wifi.min_rssi_misconfig`` -> **removal only** of min-RSSI (never a set, ever).
* ``wired.port_flapping`` (PoE reboot-loop / fault) -> a single PoE port power-cycle.

Everything whose real fix is physical -- ``wired.bad_cable``, ``wifi.mesh_uplink``
RSSI, ``net.coverage_hole`` -- and any detector without a safe template returns an
*advisory* plan: ``steps == []``, ``manual_action_required``, and a note saying
what a human must do on site. The planner never invents a network mutation for a
problem a cable or an antenna has to solve.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping, Optional

from netadmin.domain.entities import Finding
from netadmin.domain.types import EntityType
from netadmin.fixes.models import ActionType, FixPlan, FixStep, Precondition, RiskLevel

__all__ = [
    "plan_fix",
    "PHYSICAL_REFUSAL_KEYS",
    "TX_POWER_ORDER",
]

# Detectors whose remediation is physical: an advisory plan, never a mutation.
PHYSICAL_REFUSAL_KEYS = frozenset(
    {
        "wired.bad_cable",
        "wifi.mesh_uplink",
        "net.coverage_hole",
    }
)

# Non-overlapping 2.4 GHz channels; the only band we auto-plan a channel move for
# (5/6 GHz channel choice needs DFS/RF planning we do not attempt automatically).
_VALID_24_CHANNELS = (1, 6, 11)

# tx-power modes ordered quietest -> loudest; a step-down moves one left.
TX_POWER_ORDER = ("low", "medium", "high")


# ---------------------------------------------------------------------------- #
# Public entry point
# ---------------------------------------------------------------------------- #
def plan_fix(
    finding: Finding,
    *,
    device: Optional[Mapping[str, Any]] = None,
    issue_id: Optional[int] = None,
) -> FixPlan:
    """Map a finding to a :class:`FixPlan`.

    ``device`` is the raw controller device object (with ``_id``, ``mac``,
    ``radio_table``) captured read-only; required to render the radio/PoE payloads.
    When a template needs a snapshot it does not have, or the evidence describes a
    sub-case with no safe automatic fix, the planner returns an advisory plan rather
    than guessing.
    """
    key = finding.detector_key
    native = finding.entity.native_id

    if key in PHYSICAL_REFUSAL_KEYS:
        return _advisory(
            finding,
            issue_id,
            _physical_note(key, native),
        )

    if key == "wifi.min_rssi_misconfig":
        return _plan_min_rssi_remove(finding, device, issue_id)
    if key == "wifi.channel_plan":
        return _plan_channel_change(finding, device, issue_id)
    if key == "wifi.tx_power_loud":
        return _plan_tx_power_step_down(finding, device, issue_id)
    if key == "wired.port_flapping":
        return _plan_poe_power_cycle(finding, device, issue_id)

    return _advisory(
        finding,
        issue_id,
        f"No safe automatic fix for '{key}'. Review the issue evidence and remediate manually.",
    )


# ---------------------------------------------------------------------------- #
# Templates
# ---------------------------------------------------------------------------- #
def _plan_min_rssi_remove(
    finding: Finding, device: Optional[Mapping[str, Any]], issue_id: Optional[int]
) -> FixPlan:
    """Remove (disable) min-RSSI on the offending radio. Removal only -- never a set.

    Safe on every case the detector fires for (mesh-uplink AP, single-AP site,
    over-strict floor): disabling only ever *stops* clients being kicked, so it can
    never worsen coverage. Setting min-RSSI as a remediation is categorically
    refused elsewhere; this template exists solely to turn it off.
    """
    band_code = _band_code(finding)
    dev_id, radio_table, radio = _locate_radio(device, band_code)
    if dev_id is None or radio is None:
        return _advisory(
            finding, issue_id, "Device radio snapshot unavailable; disable min-RSSI manually."
        )

    if not _truthy(radio.get("min_rssi_enabled")):
        return _advisory(
            finding, issue_id, "min-RSSI already disabled on this radio; no change needed."
        )

    new_table = copy.deepcopy(list(radio_table))
    for entry in new_table:
        if entry.get("radio") == band_code:
            entry["min_rssi_enabled"] = False

    endpoint = f"rest/device/{dev_id}"
    payload = {"radio_table": new_table}
    label = finding.entity.name or finding.entity.native_id
    step = FixStep(
        action=ActionType.MIN_RSSI_REMOVE,
        target_entity_type=EntityType.RADIO,
        target_native_id=finding.entity.native_id,
        description=f"Disable min-RSSI on {label} (removal only).",
        risk=RiskLevel.LOW,
        method="PUT",
        endpoint=endpoint,
        payload=payload,
        precondition=Precondition(
            target_native_id=finding.entity.native_id,
            expected={"min_rssi_enabled": True},
            description="min-RSSI must still be enabled on this radio.",
        ),
        before={"method": "PUT", "endpoint": endpoint, "body": {"radio_table": list(radio_table)}},
        after={"method": "PUT", "endpoint": endpoint, "body": payload},
        revertible=True,
    )
    return FixPlan(
        detector_key=finding.detector_key,
        entity_native_id=finding.entity.native_id,
        title=f"Remove min-RSSI on {label}",
        steps=[step],
        issue_id=issue_id,
    )


def _plan_channel_change(
    finding: Finding, device: Optional[Mapping[str, Any]], issue_id: Optional[int]
) -> FixPlan:
    """Move a 2.4 GHz radio onto the 1/6/11 grid (off-grid or co-channel sub-cases).

    Only the deterministic 2.4 GHz cases are auto-planned. Width changes
    (``wide_channel_*``) and any 5/6 GHz case are advisory: choosing a 5 GHz channel
    safely means reasoning about DFS and neighbor occupancy the store does not hold.
    """
    band = str(finding.evidence.get("band") or "")
    subtype = str(finding.evidence.get("subtype") or finding.dims.get("subtype") or "")
    if band != "2.4" or subtype not in ("channel_off_grid", "co_channel_reuse"):
        return _advisory(
            finding,
            issue_id,
            f"Channel-plan sub-case '{subtype or '?'}' on {band or '?'} GHz needs manual "
            "RF planning (width/DFS/neighbor occupancy); not auto-planned.",
        )

    band_code = _band_code(finding)
    dev_id, radio_table, radio = _locate_radio(device, band_code)
    if dev_id is None or radio is None:
        return _advisory(
            finding, issue_id, "Device radio snapshot unavailable; set the channel manually."
        )

    current = _as_int(radio.get("channel"))
    if current is None:
        current = _as_int(finding.evidence.get("channel"))
    target = _recommend_24_channel(current, subtype)
    if target is None or target == current:
        return _advisory(
            finding, issue_id, "No better 2.4 GHz channel available to recommend automatically."
        )

    new_table = copy.deepcopy(list(radio_table))
    for entry in new_table:
        if entry.get("radio") == band_code:
            entry["channel"] = target

    endpoint = f"rest/device/{dev_id}"
    payload = {"radio_table": new_table}
    label = finding.entity.name or finding.entity.native_id
    step = FixStep(
        action=ActionType.CHANNEL_CHANGE,
        target_entity_type=EntityType.RADIO,
        target_native_id=finding.entity.native_id,
        description=f"Change {label} 2.4 GHz channel {current} -> {target} ({subtype}).",
        risk=RiskLevel.MEDIUM,
        method="PUT",
        endpoint=endpoint,
        payload=payload,
        precondition=Precondition(
            target_native_id=finding.entity.native_id,
            expected={"channel": current},
            description=f"Radio must still be on channel {current}.",
        ),
        before={"method": "PUT", "endpoint": endpoint, "body": {"radio_table": list(radio_table)}},
        after={"method": "PUT", "endpoint": endpoint, "body": payload},
        revertible=True,
    )
    return FixPlan(
        detector_key=finding.detector_key,
        entity_native_id=finding.entity.native_id,
        title=f"Retune {label} to 2.4 GHz channel {target}",
        steps=[step],
        issue_id=issue_id,
    )


def _plan_tx_power_step_down(
    finding: Finding, device: Optional[Mapping[str, Any]], issue_id: Optional[int]
) -> FixPlan:
    """Step the loud radio's tx-power down one level (never below ``low``)."""
    subtype = str(finding.evidence.get("subtype") or finding.dims.get("subtype") or "loud_power")
    if subtype != "loud_power":
        return _advisory(
            finding,
            issue_id,
            f"tx-power sub-case '{subtype}' is a coverage-balance judgement; adjust manually.",
        )

    band_code = _band_code(finding)
    dev_id, radio_table, radio = _locate_radio(device, band_code)
    if dev_id is None or radio is None:
        return _advisory(
            finding, issue_id, "Device radio snapshot unavailable; lower tx-power manually."
        )

    current_mode = str(
        radio.get("tx_power_mode") or finding.evidence.get("tx_power_mode") or ""
    ).lower()
    target_mode = _step_down_power(current_mode)
    if target_mode is None:
        return _advisory(
            finding,
            issue_id,
            f"tx-power already at its lowest ('{current_mode or '?'}'); no safe step-down.",
        )

    new_table = copy.deepcopy(list(radio_table))
    for entry in new_table:
        if entry.get("radio") == band_code:
            entry["tx_power_mode"] = target_mode

    endpoint = f"rest/device/{dev_id}"
    payload = {"radio_table": new_table}
    label = finding.entity.name or finding.entity.native_id
    step = FixStep(
        action=ActionType.TX_POWER_STEP_DOWN,
        target_entity_type=EntityType.RADIO,
        target_native_id=finding.entity.native_id,
        description=f"Step {label} tx-power {current_mode or '?'} -> {target_mode}.",
        risk=RiskLevel.LOW,
        method="PUT",
        endpoint=endpoint,
        payload=payload,
        precondition=Precondition(
            target_native_id=finding.entity.native_id,
            expected={"tx_power_mode": current_mode},
            description=f"Radio tx-power must still be '{current_mode}'.",
        ),
        before={"method": "PUT", "endpoint": endpoint, "body": {"radio_table": list(radio_table)}},
        after={"method": "PUT", "endpoint": endpoint, "body": payload},
        revertible=True,
    )
    return FixPlan(
        detector_key=finding.detector_key,
        entity_native_id=finding.entity.native_id,
        title=f"Lower tx-power on {label} to {target_mode}",
        steps=[step],
        issue_id=issue_id,
    )


def _plan_poe_power_cycle(
    finding: Finding, device: Optional[Mapping[str, Any]], issue_id: Optional[int]
) -> FixPlan:
    """Power-cycle a PoE port, but only for the reboot-loop / PoE-fault sub-case.

    A flapping port whose PoE draw drops to zero between flaps is a device stuck in
    a reboot loop -- a power-cycle is the right, reversible-by-nature nudge. A
    flapping port with no PoE-reboot signal is a physical fault (cable/connector):
    that is advisory, because cycling power fixes nothing a cable caused.
    """
    reboot_loop = _truthy(finding.evidence.get("poe_reboot_loop"))
    poe_fault = _truthy(finding.evidence.get("poe_fault"))
    if not (reboot_loop or poe_fault):
        return _advisory(
            finding,
            issue_id,
            "Port flapping without a PoE reboot-loop signal points at a physical cable/"
            "connector fault; inspect the run on site rather than power-cycling.",
        )

    sw_mac, port_idx = _split_port_native(finding.entity.native_id)
    if sw_mac is None or port_idx is None:
        return _advisory(
            finding,
            issue_id,
            "Could not resolve switch/port from the entity; power-cycle manually.",
        )

    endpoint = "cmd/devmgr"
    payload = {"cmd": "power-cycle", "mac": sw_mac, "port_idx": port_idx}
    label = finding.entity.name or finding.entity.native_id
    # A power-cycle is a transient command, not a persisted config change: there is
    # no stored config to restore, so the step is not revertible (before=None).
    expected: dict[str, Any] = {}
    if device is not None:
        port = _find_port(device, port_idx)
        if port is not None and port.get("poe_mode") is not None:
            expected = {"poe_mode": port.get("poe_mode")}
    step = FixStep(
        action=ActionType.POE_POWER_CYCLE,
        target_entity_type=EntityType.PORT,
        target_native_id=finding.entity.native_id,
        description=f"Power-cycle PoE on {label} (port {port_idx} of {sw_mac}).",
        risk=RiskLevel.MEDIUM,
        method="POST",
        endpoint=endpoint,
        payload=payload,
        precondition=Precondition(
            target_native_id=finding.entity.native_id,
            expected=expected,
            description="Port must still be the flapping PoE port.",
        ),
        before=None,
        after={"method": "POST", "endpoint": endpoint, "body": payload},
        revertible=False,
    )
    return FixPlan(
        detector_key=finding.detector_key,
        entity_native_id=finding.entity.native_id,
        title=f"Power-cycle PoE port {port_idx} on {sw_mac}",
        steps=[step],
        issue_id=issue_id,
    )


# ---------------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------------- #
def _advisory(finding: Finding, issue_id: Optional[int], note: str) -> FixPlan:
    """A step-less plan: manual action required, with a human-readable note."""
    return FixPlan(
        detector_key=finding.detector_key,
        entity_native_id=finding.entity.native_id,
        title=f"Manual action required: {finding.title}",
        steps=[],
        advisory=note,
        manual_action_required=True,
        issue_id=issue_id,
    )


def _physical_note(key: str, native: str) -> str:
    notes = {
        "wired.bad_cable": (
            f"{native}: replace or reseat the cable/SFP and re-test the run. "
            "No controller setting fixes a physical link fault."
        ),
        "wifi.mesh_uplink": (
            f"{native}: the wireless uplink RSSI is too weak. Reposition the AP, add a "
            "wired backhaul, or add a relay node. Not a controller-side change."
        ),
        "net.coverage_hole": (
            f"{native}: clients see no acceptable AP here. Add or reposition an AP to "
            "cover the dead zone. Not a controller-side change."
        ),
    }
    return notes.get(key, f"{native}: manual, on-site remediation required.")


def _band_code(finding: Finding) -> Optional[str]:
    """The controller radio code ('ng'/'na'/'6e') from the RADIO entity native id."""
    native = finding.entity.native_id
    if native and ":" in native:
        return native.rsplit(":", 1)[-1]
    raw = finding.entity.meta.get("band") if finding.entity.meta else None
    return str(raw) if raw is not None else None


def _locate_radio(
    device: Optional[Mapping[str, Any]], band_code: Optional[str]
) -> tuple[Optional[str], list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Resolve (device_id, radio_table, target radio dict) from a raw device object."""
    if device is None or band_code is None:
        return None, [], None
    dev_id = device.get("_id") or device.get("id")
    radio_table = list(device.get("radio_table") or [])
    if not dev_id or not radio_table:
        return None, radio_table, None
    target = next((r for r in radio_table if r.get("radio") == band_code), None)
    return str(dev_id), radio_table, target


def _find_port(device: Mapping[str, Any], port_idx: int) -> Optional[dict[str, Any]]:
    for port in device.get("port_table") or []:
        if _as_int(port.get("port_idx")) == port_idx:
            return port
    return None


def _split_port_native(native: str) -> tuple[Optional[str], Optional[int]]:
    """Split a port native id ``"<sw_mac>:<port_idx>"`` into its parts."""
    if not native or ":" not in native:
        return None, None
    mac, _, idx = native.rpartition(":")
    return (mac or None), _as_int(idx)


def _recommend_24_channel(current: Optional[int], subtype: str) -> Optional[int]:
    """Pick a 1/6/11 channel: nearest grid slot for off-grid, a rotation for reuse."""
    if subtype == "channel_off_grid":
        if current is None:
            return _VALID_24_CHANNELS[0]
        return min(_VALID_24_CHANNELS, key=lambda c: (abs(c - current), c))
    if subtype == "co_channel_reuse":
        # Deterministic rotation onto the next non-overlapping channel.
        rotation = {1: 6, 6: 11, 11: 1}
        if current in rotation:
            return rotation[current]
        return _VALID_24_CHANNELS[0]
    return None


def _step_down_power(mode: str) -> Optional[str]:
    """One level quieter: high->medium, medium->low, auto->medium. None at floor."""
    mode = (mode or "").lower()
    if mode == "auto":
        return "medium"
    if mode in TX_POWER_ORDER:
        idx = TX_POWER_ORDER.index(mode)
        if idx > 0:
            return TX_POWER_ORDER[idx - 1]
        return None  # already at "low"
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return False


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
