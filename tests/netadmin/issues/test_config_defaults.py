"""Finding 11: EngineConfig defaults the inhibition sources to M=1.

``infra.controller_down`` and ``infra.device_down`` must activate (and start
inhibiting) on their first fire, even with a bare EngineConfig -- an inhibitor
that waited the default M=3 cycles would let noise through before the freeze
took hold (section 7).
"""

from __future__ import annotations

from netadmin.domain.types import IssueState
from netadmin.issues.engine import IssueEngine, fingerprint
from netadmin.issues.models import EngineConfig

TS = 1_700_000_000


def test_bare_config_seeds_inhibition_source_m() -> None:
    cfg = EngineConfig()
    assert cfg.m_for("infra.controller_down") == 1
    assert cfg.m_for("infra.device_down") == 1
    # A non-inhibitor detector keeps the default M.
    assert cfg.m_for("wired.bad_cable") == 3


def test_explicit_override_wins_but_other_source_still_seeded() -> None:
    cfg = EngineConfig(detector_m={"infra.controller_down": 5})
    assert cfg.m_for("infra.controller_down") == 5  # caller override respected
    assert cfg.m_for("infra.device_down") == 1  # still seeded to the default M=1


def test_controller_down_activates_first_fire_under_default_config(repo, make_finding) -> None:
    # No manual detector_m: the default config alone must let the cause activate
    # immediately so its inhibition is armed on the very first cycle.
    engine = IssueEngine(repo, config=EngineConfig())
    controller = make_finding("infra.controller_down", native_id="controller")
    engine.process_cycle(TS, findings=[controller])
    issue = repo.get_open_issue_by_fingerprint(fingerprint(controller))
    assert issue is not None
    assert issue.state is IssueState.ACTIVE


def test_device_down_activates_first_fire_under_default_config(repo, make_finding) -> None:
    engine = IssueEngine(repo, config=EngineConfig())
    device = make_finding("infra.device_down", native_id="sw-1")
    engine.process_cycle(TS, findings=[device])
    issue = repo.get_open_issue_by_fingerprint(fingerprint(device))
    assert issue is not None
    assert issue.state is IssueState.ACTIVE
