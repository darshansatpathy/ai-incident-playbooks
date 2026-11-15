"""Small builders so each test states only what it cares about."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from playbooks.model import (
    Event,
    Facts,
    Incident,
    Level,
    Library,
    Obligation,
    Playbook,
    Policy,
    Role,
    SeverityRule,
    Step,
)

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 15, 10, 0, tzinfo=UTC)
AWARE = T0 - timedelta(minutes=30)
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def at(minutes: float, base: datetime = T0) -> datetime:
    return base + timedelta(minutes=minutes)


def obligation(id: str = "ob1", **kw: object) -> Obligation:
    base: dict[str, object] = {
        "id": id,
        "kind": "legal",
        "audience": "someone",
        "when": {"data_exposed_in": ("personal",)},
        "clock_from": "aware",
        "deadline_hours": 48,
        "example": False,
        "source": "src",
        "reviewed_by": "reviewer",
        "reviewed_on": "2026-01-01",
    }
    base.update(kw)
    return Obligation(**base)  # type: ignore[arg-type]


def policy(**kw: object) -> Policy:
    base: dict[str, object] = {
        "phases": ("detect", "contain", "notify", "review"),
        "required_phases": ("contain", "review"),
        "contain_within": {"sev1": 30, "sev2": 90},
        "kinds": ("data_exposure",),
        "levels": (Level("sev1", 15, 60), Level("sev2", 30, 120), Level("sev3", 120, 480)),
        "rules": (
            SeverityRule("sev1", "physical harm", {"harm_in": ("physical",)}),
            SeverityRule("sev2", "personal data", {"data_exposed_in": ("personal",)}),
            SeverityRule("sev2", "many people", {"users_affected_min": 100}),
        ),
        "roles": {
            "ic": Role("ic", "eng", False),
            "eng": Role("eng", "sec", False),
            "sec": Role("sec", "exec", False),
            "legal": Role("legal", "exec", False),
            "exec": Role("exec", "", True),
        },
        "people": {
            "p1": ("ic",),
            "p2": ("eng",),
            "p3": ("sec",),
            "p4": ("exec",),
            "p5": ("legal",),
        },
        "obligations": (
            obligation(),
            obligation(
                "ob2",
                kind="internal",
                when={"autonomous_action": True},
                clock_from="declared",
                deadline_hours=4,
            ),
        ),
    }
    base.update(kw)
    return Policy(**base)  # type: ignore[arg-type]


def step(
    id: str,
    phase: str,
    role: str,
    due: dict[str, int],
    *requires: str,
    notifies: str = "",
    evidence: str = "none",
) -> Step:
    return Step(id, phase, role, f"do {id}", due, tuple(requires), evidence, notifies)


def playbook(steps: tuple[Step, ...] | None = None, **kw: object) -> Playbook:
    default = (
        step("s-detect", "detect", "sec", {"sev1": 10, "sev2": 30, "sev3": 60}),
        step("s-contain", "contain", "eng", {"sev1": 20, "sev2": 60}, "s-detect"),
        step(
            "s-notify", "notify", "legal", {"sev1": 600, "sev2": 600}, "s-contain", notifies="ob1"
        ),
        step("s-review", "review", "ic", {"sev1": 5000, "sev2": 5000, "sev3": 5000}, "s-contain"),
        step("s-brief", "notify", "ic", {"sev1": 240, "sev2": 240}, "s-detect", notifies="ob2"),
    )
    base: dict[str, object] = {
        "id": "pb1",
        "title": "A playbook",
        "applies_to": ("data_exposure",),
        "steps": steps or default,
        "file_stem": "pb1",
    }
    base.update(kw)
    return Playbook(**base)  # type: ignore[arg-type]


def event(
    step_id: str, minutes: float, by: str = "p2", kind: str = "step", evidence: str = "x"
) -> Event:
    return Event(at(minutes), kind, step_id, by, "", evidence)


def incident(*events: Event, **kw: object) -> Incident:
    base: dict[str, object] = {
        "id": "inc1",
        "title": "An incident",
        "kind": "data_exposure",
        "playbook": "pb1",
        "declared_at": T0,
        "aware_at": AWARE,
        "declared_severity": "sev2",
        "status": "open",
        "facts": Facts(data_exposed="personal"),
        "events": events,
        "file_stem": "inc1",
    }
    base.update(kw)
    return Incident(**base)  # type: ignore[arg-type]


def library(
    *incidents: Incident,
    pol: Policy | None = None,
    pbs: list[Playbook] | None = None,
) -> Library:
    return Library(
        pol or policy(),
        {p.id: p for p in (pbs if pbs is not None else [playbook()])},
        {i.id: i for i in incidents},
    )
