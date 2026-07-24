"""The detector catalog — the registry the engine iterates (section 6).

Every detector is registered once here with its metadata: its ``key`` / ``scope``
/ ``cadence`` (carried on the detector itself, per the ``Detector`` protocol), a
**severity ceiling** the engine clamps every finding to, and a **title template**
for the UI/dossier. Registration is an explicit list, not import side-effects, so
the wiring is greppable and the import graph is acyclic: this module imports the
detector classes; the detectors import only the engine's ``UNKNOWN`` sentinel;
the engine imports this catalog lazily. Duplicate keys are a hard error —
:func:`build_catalog` raises rather than let two detectors share a fingerprint
namespace.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Optional, Protocol, Sequence, runtime_checkable

from netadmin.domain.types import Cadence, EntityType, Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from netadmin.detect.context import DetectorContext
    from netadmin.detect.engine import EvalResult


@runtime_checkable
class Detector(Protocol):
    """A registered detector (section 6).

    ``key`` is the stable identity that anchors every issue fingerprint and every
    threshold-override section. ``scope`` is the primary entity type the detector
    concerns (a catalog/UI grouping hint — a detector may inspect related types
    internally). ``cadence`` selects the tier the engine runs it in. ``evaluate``
    returns a (possibly empty) ``list[Finding]`` — an empty list is a *clear*
    evaluation — or the engine's ``UNKNOWN`` sentinel when a coverage gap makes the
    verdict untrustworthy.
    """

    key: str
    scope: EntityType
    cadence: Cadence

    def evaluate(self, ctx: "DetectorContext") -> "EvalResult":
        """Return findings (empty list = clear) or the ``UNKNOWN`` sentinel."""


@dataclass(frozen=True)
class Playbook:
    """The admin's field guide for a detector (ARCHITECTURE.md section 6 table).

    Carried on the catalog so the LLM-investigator dossier (section 10) can print
    the same signature/confounder/fix guidance a human admin would consult. This
    is metadata *about* the detector, distinct from a :class:`Finding`'s per-issue
    ``confounders_checked`` audit trail: the playbook names every trap the class
    of problem is known for, whether or not this instance tested it.
    """

    signature: str
    confounders: str = ""
    fix_guidance: str = ""


@dataclass(frozen=True)
class CatalogEntry:
    """A detector plus the catalog metadata the engine and UI need."""

    detector: Detector
    severity_ceiling: Severity
    title_template: str
    playbook: Optional[Playbook] = None

    @property
    def key(self) -> str:
        return self.detector.key

    @property
    def scope(self) -> EntityType:
        return self.detector.scope

    @property
    def cadence(self) -> Cadence:
        return self.detector.cadence


class Catalog:
    """An immutable, key-indexed set of :class:`CatalogEntry` records."""

    def __init__(self, entries: Sequence[CatalogEntry]) -> None:
        by_key: dict[str, CatalogEntry] = {}
        for entry in entries:
            if entry.key in by_key:
                raise ValueError(f"duplicate detector key in catalog: {entry.key!r}")
            by_key[entry.key] = entry
        self._by_key = by_key
        self._entries = tuple(entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    @property
    def entries(self) -> tuple[CatalogEntry, ...]:
        return self._entries

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(self._by_key)

    def get(self, key: str) -> CatalogEntry:
        """The entry for ``key`` (raises ``KeyError`` if unregistered)."""
        return self._by_key[key]

    def by_cadence(self, cadence: Cadence) -> list[CatalogEntry]:
        """Registered entries of ``cadence``, in registration order."""
        return [e for e in self._entries if e.cadence is cadence]

    def by_scope(self, scope: EntityType) -> list[CatalogEntry]:
        return [e for e in self._entries if e.scope is scope]


def build_catalog(entries: Sequence[CatalogEntry]) -> Catalog:
    """Build a :class:`Catalog`, raising on any duplicate detector key."""
    return Catalog(entries)


# Field-guide text for every catalog-v1 detector, lifted from the ARCHITECTURE.md
# section 6 signature table (signature + confounders) and the section 9 fix
# planner (fix guidance). Keyed by ``detector_key`` and stitched onto each
# CatalogEntry in :func:`_default_entries`. The dossier (section 10) prints the
# entry for whichever detector opened the issue.
_PLAYBOOKS: dict[str, Playbook] = {
    "infra.controller_down": Playbook(
        signature="Lost-contact events plus consecutive poll failures against the controller.",
        confounders="Transient network blip vs a genuine outage; local collector network path.",
        fix_guidance="Restore controller connectivity/power and verify the network path. "
        "While it is down, every other detector is inhibited (absence of evidence is not "
        "evidence of absence).",
    ),
    "infra.device_down": Playbook(
        signature="Lost-contact events plus poll failures for a specific AP/switch/gateway.",
        confounders="Planned reboot/firmware upgrade window; upstream device down (parent).",
        fix_guidance="Check power/PoE on the port, the uplink cable, then reboot the device. "
        "A downed switch inhibits its own ports' issues.",
    ),
    "wired.bad_cable": Playbook(
        signature="rx_errors delta rate > 10/min sustained or > 0.001% of packets; OR a "
        "gigabit-capable peer negotiated at 10/100 (broken-pair downshift).",
        confounders="Known 100 Mbps device classes; counter age (a stale cumulative counter); "
        "an unmanaged-switch hop hiding the real port.",
        fix_guidance="Reseat then replace the patch cable; re-test the run. On an uplink port "
        "this is P1 — the whole segment rides it.",
    ),
    "wired.duplex_mismatch": Playbook(
        signature="full_duplex=false on a modern link that should negotiate full duplex.",
        confounders="Legacy half-duplex device that is correct as-is.",
        fix_guidance="Set both ends to auto-negotiate (or matching forced full-duplex). "
        "A one-sided forced setting is the usual cause.",
    ),
    "wired.port_flapping": Playbook(
        signature="≥5 link transitions/10 min or ≥10/h from events; infra ports weighted higher; "
        "PoE draw dropping to 0 between flaps signals a reboot loop.",
        confounders="A laptop docking/undocking; scheduled device reboots.",
        fix_guidance="Reseat cable/SFP; on a PoE reboot loop check the PoE budget and power-"
        "cycle the port; replace the cable if errors persist.",
    ),
    "wired.uplink_saturation": Playbook(
        signature="Uplink bps > 80%/95% of negotiated speed for 5 min+ with rising tx_dropped; "
        "compared against the hour-of-day baseline first.",
        confounders="A one-off backup/transfer; expected peak-hour load.",
        fix_guidance="Add capacity (LAG or a faster uplink), shape/prioritise traffic, or "
        "rebalance devices across uplinks.",
    ),
    "wired.poe_budget": Playbook(
        signature="Sum of poe_power > 80%/90% of the switch budget; EVT_SW_PoeOverload.",
        confounders="A momentary inrush at device power-on.",
        fix_guidance="Redistribute PoE devices across switches, disable non-essential PoE ports, "
        "or move to a higher-budget PSU/switch.",
    ),
    "wired.stp_loop": Playbook(
        signature="EVT_SW_StpPortBlocking and stp_state churn.",
        confounders="Expected STP reconvergence after a planned topology change.",
        fix_guidance="Find and remove the physical loop (a duplicate cable between switches); "
        "confirm STP is enabled fleet-wide. No safe auto-fix.",
    ),
    "wired.broadcast_storm": Playbook(
        signature="Broadcast/multicast pps > 10× the 24 h baseline on multiple ports at once.",
        confounders="A legitimate multicast burst (imaging, discovery sweep).",
        fix_guidance="Enable storm control, locate the offending port/device, and rule out a "
        "loop feeding the storm.",
    ),
    "wired.sfp_degraded": Playbook(
        signature="sfp_rxpower drifting toward the threshold, or sfp_txfault/rxfault flags.",
        confounders="A cold-start reading before the optic stabilises.",
        fix_guidance="Clean or replace the fiber, then replace the SFP module if RX power stays low.",
    ),
    "wifi.sticky_client": Playbook(
        signature="RSSI < −75 sustained ≥ 10 min while a historically-better AP exists for this "
        "client; corroborated by low rates and high retries.",
        confounders="No better AP in the client's history — that is a coverage hole, a different "
        "issue, not a sticky client.",
        fix_guidance="Tune min-RSSI or band steering to nudge the client off; review AP placement "
        "if it clusters on one AP.",
    ),
    "wifi.pingpong_roamer": Playbook(
        signature="Two APs, ≥ 4 roams ≤ 10 s apart (Meraki definition); stationary devices flagged "
        "at > 4-6/h (suspicious) and > 10-15/h (definite).",
        confounders="A genuinely mobile device walking a boundary between cells.",
        fix_guidance="Add min-RSSI hysteresis, reduce overlapping-cell tx-power, and enable "
        "sticky-client / roaming assistance.",
    ),
    "wifi.roam_quality": Playbook(
        signature="Roam events where post-roam RSSI is > 10 dB worse, or roam latency crosses its tier.",
        confounders="A roam into a deliberately weaker overflow cell.",
        fix_guidance="Tune coverage/power overlap; enable 802.11r/k/v where the client fleet supports it.",
    ),
    "wifi.min_rssi_misconfig": Playbook(
        signature="min-RSSI enabled on a mesh-uplink AP (latent outage), on a single-AP site, or "
        "set stricter than −70.",
        confounders="A dense multi-AP site where a moderate min-RSSI is correct.",
        fix_guidance="Remove min-RSSI on mesh-uplink and single-AP sites; relax any value stricter "
        "than −70. Never raise it on a mesh AP.",
    ),
    "wifi.channel_plan": Playbook(
        signature="2.4 GHz off 1/6/11, 40 MHz on 2.4, same-channel neighbors with mutual RSSI "
        "> −75, or 80 MHz width with 4+ APs.",
        confounders="A single-AP site where width/overlap does not matter.",
        fix_guidance="Set 2.4 GHz to 1/6/11 at 20 MHz, narrow 5 GHz width under density, and "
        "re-plan channels to cut co-channel overlap.",
    ),
    "wifi.dfs_recurring": Playbook(
        signature="EVT_AP_RadarDetected ≥ 1/day, or a repeating same-hour radar pattern.",
        confounders="A one-off radar hit — not yet a pattern.",
        fix_guidance="Move that AP/radio to a non-DFS channel to stop the recurring CAC blackouts.",
    ),
    "wifi.airtime_saturation": Playbook(
        signature="cu_total > 50% sustained (degraded) / > 80% (critical); self vs non-self "
        "utilization split for the fix path.",
        confounders="A brief high-throughput burst; expected peak-hour airtime.",
        fix_guidance="If self-utilization: reduce channel width, add capacity, steer to 5/6 GHz. "
        "If non-self: mitigate the interferer or re-plan the channel.",
    ),
    "wifi.tx_power_loud": Playbook(
        signature="Multi-AP site running High/auto-max power; corroborated by sticky-client "
        "concentration and 2.4 GHz not held ~6 dB below 5 GHz.",
        confounders="A large open space that genuinely needs the power.",
        fix_guidance="Step tx-power down and keep 2.4 GHz ~6 dB below 5 GHz so cells do not "
        "over-reach and create sticky clients.",
    ),
    "wifi.legacy_rates": Playbook(
        signature="802.11b clients present, or the minimum basic rate left at 1 Mbps.",
        confounders="A site that must support legacy IoT on 802.11b.",
        fix_guidance="Disable legacy 802.11b rates and raise the minimum basic rate to reclaim airtime.",
    ),
    "wifi.band_steering": Playbook(
        signature="Dual-band client parked on 2.4 GHz at strong RSSI with an idle 5 GHz on the "
        "same AP; inverse: held on 5 GHz at ≤ −80.",
        confounders="A 2.4-GHz-only client that cannot move.",
        fix_guidance="Enable/tune band steering so capable clients ride 5 GHz where the signal supports it.",
    ),
    "wifi.mesh_uplink": Playbook(
        signature="Wireless uplink RSSI worse than −65/−70, hop count ≥ 3, or reconnect cycles; "
        "also a wired AP with meshing still enabled.",
        confounders="A deliberately meshed edge AP with an acceptable link.",
        fix_guidance="Improve mesh-AP placement/backhaul or add a wired drop; disable meshing on "
        "APs that are actually wired.",
    ),
    "wifi.rogue_ap": Playbook(
        signature="A strong (> −75 dBm at a reporting AP), persistent-across-scans neighbor/rogue "
        "BSS co-channel with one of our radios (or adjacent-overlapping on 2.4 GHz).",
        confounders="Our own hardware or a known-BSSID allowlist (config-driven); a transient "
        "one-scan sighting; a distant weak neighbor (advisory only, not fired).",
        fix_guidance="Move the affected radio to a clearer channel; if it is our own hardware or a "
        "benign neighbor, add its BSSID to the allowlist. P2 only when it overlaps a congested radio.",
    ),
    "client.flaky": Playbook(
        signature="Reason-code-weighted disconnects (codes 1/2/3/7/15 pathological, 8 benign) "
        "above tier, then the attribution matrix (one client+one AP = device-or-deadspot; "
        "one client+many APs = device; many clients+one AP = AP fault; many bad-RSSI clients on "
        "one AP = coverage hole).",
        confounders="Benign reason code 8 (normal deauth); a single dead spot mistaken for a bad device.",
        fix_guidance="Follow the attribution: patch the device driver/firmware, service the AP, or "
        "remediate coverage — the matrix says which.",
    ),
    "client.dhcp": Playbook(
        signature="169.254.x self-assigned addresses, association-without-IP > 30 s, or pool "
        "utilization > 85% on a UniFi gateway.",
        confounders="A single misconfigured static-IP client vs a network-wide pool exhaustion.",
        fix_guidance="Check the DHCP server/relay and VLAN; enlarge the pool or shorten leases if "
        "utilization is the cause. Network-wide is P1.",
    ),
    "client.known_pathology": Playbook(
        signature="Device-class knowledge base (ESP32 vs PMF/11r, iOS −70 roam scan, Sonos vs "
        "IGMPv3) matched against observed symptoms and the WLAN config.",
        confounders="A symptom that merely resembles a known pathology without the device class.",
        fix_guidance="Apply the device-class-specific WLAN setting (e.g. relax PMF/11r for ESP32, "
        "enable IGMP snooping for Sonos).",
    ),
    "wan.isp_degraded": Playbook(
        signature="Windowed probe-latency p50 sustained above ratio×(7-day baseline p50) across "
        "several 15-min windows, and/or the per-window failed-probe fraction sustained above the "
        "baseline fraction. Robust to Starlink's ~15 s handoff spikes (a brief minority of samples "
        "barely move a 15-min median); single-window blips never fire.",
        confounders="Starlink handoff jitter and brief obstruction dips (excluded by the sustained-"
        "multi-window rule); a local uplink-saturation event inflating latency; prober-down gaps "
        "(a coverage gap is UNKNOWN, failed probes are loss, not a gap).",
        fix_guidance="Confirm it is upstream (check the dish for obstructions/alignment on Starlink), "
        "then open an ISP ticket; fail over to a secondary WAN if one exists. No local fix. Sustained "
        "heavy loss escalates to P1.",
    ),
    "wan.bufferbloat": Playbook(
        signature="Probe RTT loaded-minus-idle > 200 ms while WAN throughput sits near the plan rate.",
        confounders="A momentary saturation spike, not sustained load.",
        fix_guidance="Enable Smart Queue Management (SQM/fq_codel) with the shaper set to ~90% of "
        "the measured plan rate.",
    ),
    "wan.flapping": Playbook(
        signature="EVT_GW_WANTransition ≥ 3 in 24 h.",
        confounders="A one-off ISP maintenance window.",
        fix_guidance="Check the WAN cable/modem and PPPoE session; escalate a repeating line to the ISP.",
    ),
    "wan.dns_slow": Playbook(
        signature="Probe: the gateway resolver > 150 ms / > 1 s sustained; compared against a "
        "public anchor to separate local from upstream.",
        confounders="A single slow lookup vs a sustained pattern; the anchor being slow too "
        "(then it is upstream, not local).",
        fix_guidance="If local: fix/replace the resolver. If upstream: switch the forwarders to a "
        "faster upstream DNS.",
    ),
    "net.coverage_hole": Playbook(
        signature="Cisco CHD adapted per-AP client-RSSI histogram: p25 < −75 or > 20% of "
        "client-hours < −80, and no better AP in those clients' history.",
        confounders="A transient cluster of far clients; a room nobody normally uses.",
        fix_guidance="Add or relocate an AP to fill the hole; raise power only as a stopgap — "
        "placement is the real fix.",
    ),
    "net.firmware_regression": Playbook(
        signature="Change-point on upgrade events: 7 d pre/post per device on disconnects/client-"
        "hour, port errors, radio resets; escalates when the same model+version degrades the "
        "fleet. First 2 h post-upgrade excluded.",
        confounders="Normal post-upgrade settling in the first 2 hours; an unrelated coincident change.",
        fix_guidance="Roll the affected device(s) back to the prior known-good firmware and hold "
        "fleet-wide upgrades on that build.",
    ),
    "wan.latency_shift": Playbook(
        signature="A sustained CUSUM change-point in WAN latency: the post-shift regime sits well "
        "above the prior baseline median, holding rather than spiking.",
        confounders="A one-off latency spike (not a sustained regime); a local uplink-saturation "
        "event; an expected routing change.",
        fix_guidance="Correlate the shift date with ISP/routing or config changes; if it is "
        "upstream and sustained, open an ISP ticket referencing the change date.",
    ),
}


def _default_entries() -> list[CatalogEntry]:
    """The shipped catalog-v1 registrations.

    Imported inside the function so this module can be imported for its types
    (``Detector`` / ``CatalogEntry``) without eagerly pulling in every detector
    family. The detector families land here as their agents complete them.
    """
    from netadmin.detect.detectors.client import (
        DhcpClientDetector,
        FlakyClientDetector,
        KnownPathologyDetector,
    )
    from netadmin.detect.detectors.infra import ControllerDownDetector, DeviceDownDetector
    from netadmin.detect.detectors.net import CoverageHoleDetector, FirmwareRegressionDetector
    from netadmin.detect.detectors.wan import (
        BufferbloatDetector,
        DnsSlowDetector,
        IspDegradedDetector,
        LatencyShiftDetector,
        WanFlappingDetector,
    )
    from netadmin.detect.detectors.wifi import (
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
    from netadmin.detect.detectors.wired import (
        BadCableDetector,
        BroadcastStormDetector,
        DuplexMismatchDetector,
        PoeBudgetDetector,
        PortFlappingDetector,
        SfpDegradedDetector,
        StpLoopDetector,
        UplinkSaturationDetector,
    )

    entries = [
        CatalogEntry(
            detector=ControllerDownDetector(),
            severity_ceiling=Severity.P1,
            title_template="Controller unreachable",
        ),
        CatalogEntry(
            detector=DeviceDownDetector(),
            severity_ceiling=Severity.P1,
            title_template="{entity} is down",
        ),
        # --- wired.* (section 6) ---
        CatalogEntry(
            detector=BadCableDetector(),
            severity_ceiling=Severity.P1,  # P2 access, P1 on an uplink port
            title_template="Cable/link fault on {entity}",
        ),
        CatalogEntry(
            detector=DuplexMismatchDetector(),
            severity_ceiling=Severity.P2,
            title_template="Duplex mismatch on {entity}",
        ),
        CatalogEntry(
            detector=PortFlappingDetector(),
            severity_ceiling=Severity.P1,  # P2 access, P1 on an infra/uplink port
            title_template="Port flapping: {entity}",
        ),
        CatalogEntry(
            detector=UplinkSaturationDetector(),
            severity_ceiling=Severity.P2,
            title_template="Uplink saturation on {entity}",
        ),
        CatalogEntry(
            detector=PoeBudgetDetector(),
            severity_ceiling=Severity.P1,  # P2 warn, P1 critical / overload
            title_template="PoE budget pressure on {entity}",
        ),
        CatalogEntry(
            detector=StpLoopDetector(),
            severity_ceiling=Severity.P1,
            title_template="STP loop / blocking on {entity}",
        ),
        CatalogEntry(
            detector=BroadcastStormDetector(),
            severity_ceiling=Severity.P1,
            title_template="Broadcast storm on {entity}",
        ),
        CatalogEntry(
            detector=SfpDegradedDetector(),
            severity_ceiling=Severity.P2,
            title_template="SFP degraded on {entity}",
        ),
        # --- client.* (section 6) ---
        CatalogEntry(
            detector=FlakyClientDetector(),
            severity_ceiling=Severity.P2,  # P3 device, P2 by AP-fault attribution
            title_template="Client {entity} flaky",
        ),
        CatalogEntry(
            detector=DhcpClientDetector(),
            severity_ceiling=Severity.P1,  # P3 single, P1 site-wide DHCP failure
            title_template="Client {entity} DHCP failure",
        ),
        CatalogEntry(
            detector=KnownPathologyDetector(),
            severity_ceiling=Severity.P3,
            title_template="Client {entity} known pathology",
        ),
        # --- wan.* (section 6) ---
        CatalogEntry(
            detector=IspDegradedDetector(),
            severity_ceiling=Severity.P1,  # P2 latency, P1 with sustained loss
            title_template="WAN degraded",
        ),
        CatalogEntry(
            detector=LatencyShiftDetector(),
            severity_ceiling=Severity.P3,
            title_template="WAN latency regime changed",
        ),
        CatalogEntry(
            detector=DnsSlowDetector(),
            severity_ceiling=Severity.P2,
            title_template="DNS resolution slow",
        ),
        CatalogEntry(
            detector=BufferbloatDetector(),
            severity_ceiling=Severity.P2,
            title_template="Bufferbloat under load",
        ),
        CatalogEntry(
            detector=WanFlappingDetector(),
            severity_ceiling=Severity.P1,
            title_template="WAN flapping",
        ),
        # --- net.* (section 6) ---
        CatalogEntry(
            detector=CoverageHoleDetector(),
            severity_ceiling=Severity.P2,
            title_template="Coverage hole at {entity}",
        ),
        CatalogEntry(
            detector=FirmwareRegressionDetector(),
            severity_ceiling=Severity.P1,  # P2 single device, P1 fleet-wide bad build
            title_template="Firmware regression on {entity}",
        ),
        # --- wifi.* (section 6) ---
        CatalogEntry(
            detector=StickyClientDetector(),
            severity_ceiling=Severity.P2,  # P3, P2 when clustered on one AP
            title_template="Sticky client {entity}",
        ),
        CatalogEntry(
            detector=PingpongRoamerDetector(),
            severity_ceiling=Severity.P2,  # P3 suspicious, P2 definite ping-pong
            title_template="Ping-pong roamer {entity}",
        ),
        CatalogEntry(
            detector=RoamQualityDetector(),
            severity_ceiling=Severity.P3,
            title_template="Poor roam quality for {entity}",
        ),
        CatalogEntry(
            detector=MinRssiMisconfigDetector(),
            severity_ceiling=Severity.P2,  # P2 mesh/single-AP, P3 stricter-than-floor
            title_template="min-RSSI misconfigured on {entity}",
        ),
        CatalogEntry(
            detector=ChannelPlanDetector(),
            severity_ceiling=Severity.P3,
            title_template="Channel-plan issue on {entity}",
        ),
        CatalogEntry(
            detector=DfsRecurringDetector(),
            severity_ceiling=Severity.P2,  # P3 recurring, P2 same-hour clustering
            title_template="Recurring DFS radar on {entity}",
        ),
        CatalogEntry(
            detector=AirtimeSaturationDetector(),
            severity_ceiling=Severity.P1,  # P2 degraded, P1 critical
            title_template="Airtime saturation on {entity}",
        ),
        CatalogEntry(
            detector=TxPowerLoudDetector(),
            severity_ceiling=Severity.P2,  # P3, P2 with sticky concentration
            title_template="Loud tx-power on {entity}",
        ),
        CatalogEntry(
            detector=LegacyRatesDetector(),
            severity_ceiling=Severity.P3,
            title_template="Legacy-rate client {entity}",
        ),
        CatalogEntry(
            detector=BandSteeringDetector(),
            severity_ceiling=Severity.P3,
            title_template="Band-steering opportunity for {entity}",
        ),
        CatalogEntry(
            detector=MeshUplinkDetector(),
            severity_ceiling=Severity.P2,  # P2 weak uplink, P3 latent wired-mesh
            title_template="Weak mesh uplink on {entity}",
        ),
        CatalogEntry(
            detector=RogueApDetector(),
            severity_ceiling=Severity.P2,  # P3 default, P2 when it overlaps a congested radio
            title_template="Rogue/neighbor AP {entity}",
        ),
    ]

    # Stitch each detector's field-guide entry on by key; a detector without a
    # registered playbook simply carries ``None`` (the dossier degrades to a note).
    return [replace(e, playbook=_PLAYBOOKS.get(e.key)) for e in entries]


DEFAULT_CATALOG: Catalog = build_catalog(_default_entries())


__all__ = [
    "Detector",
    "CatalogEntry",
    "Playbook",
    "Catalog",
    "build_catalog",
    "DEFAULT_CATALOG",
]
