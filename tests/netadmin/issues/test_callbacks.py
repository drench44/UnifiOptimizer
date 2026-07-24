"""on_transition callbacks: fired for every transition, fire-and-forget, and a
raising callback never affects the engine or the other callbacks (section 7).
"""

from __future__ import annotations

from netadmin.domain.types import IssueState
from netadmin.issues.engine import IssueEngine, fingerprint
from netadmin.issues.models import EngineConfig, EventKind, Transition

TS = 1_700_000_000


def test_callbacks_receive_transitions(repo, make_finding) -> None:
    seen: list[Transition] = []
    engine = IssueEngine(repo, on_transition=[seen.append])

    finding = make_finding()
    for i in range(3):
        engine.process_cycle(TS + i * 60, findings=[finding])

    kinds = [t.kind for t in seen]
    assert kinds == [EventKind.DETECTED, EventKind.ESCALATED]
    escalation = seen[-1]
    assert escalation.from_state is IssueState.PENDING
    assert escalation.to_state is IssueState.ACTIVE
    assert escalation.fingerprint == fingerprint(finding)
    assert escalation.detector_key == "wired.bad_cable"


def test_raising_callback_is_isolated(repo, make_finding) -> None:
    calls: list[str] = []

    def boom(_transition: Transition) -> None:
        calls.append("boom")
        raise RuntimeError("callback blew up")

    def good(transition: Transition) -> None:
        calls.append(transition.kind)

    engine = IssueEngine(repo, config=EngineConfig(default_m=1), on_transition=[boom, good])

    finding = make_finding()
    # Must not raise despite the first callback throwing.
    engine.process_cycle(TS, findings=[finding])

    # Engine state advanced correctly...
    issue = repo.get_open_issue_by_fingerprint(fingerprint(finding))
    assert issue.state is IssueState.ACTIVE
    # ...and the second callback still ran for both events.
    assert calls.count("boom") == 2
    assert EventKind.DETECTED in calls
    assert EventKind.ESCALATED in calls


def test_add_callback_registers_after_construction(repo, make_finding) -> None:
    seen: list[Transition] = []
    engine = IssueEngine(repo, config=EngineConfig(default_m=1))
    engine.add_callback(seen.append)

    engine.process_cycle(TS, findings=[make_finding()])
    assert [t.kind for t in seen] == [EventKind.DETECTED, EventKind.ESCALATED]


def test_process_cycle_returns_same_transitions_as_callbacks(repo, make_finding) -> None:
    seen: list[Transition] = []
    engine = IssueEngine(repo, config=EngineConfig(default_m=1), on_transition=[seen.append])
    returned = engine.process_cycle(TS, findings=[make_finding()])
    assert [t.kind for t in returned] == [t.kind for t in seen]
