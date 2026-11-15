"""Classification and planning. Nothing here reads the clock: `now` is always passed in."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from playbooks.model import (
    Drill,
    Event,
    Facts,
    Incident,
    Library,
    Obligation,
    Playbook,
    Policy,
    Step,
)


def matches(when: dict[str, Any], facts: Facts) -> bool:
    """Every condition must hold. `fact_in` is membership, `fact_min` is at least, else equality."""
    for key, value in when.items():
        if key.endswith("_in"):
            ok = getattr(facts, key.removesuffix("_in")) in value
        elif key.endswith("_min"):
            ok = getattr(facts, key.removesuffix("_min")) >= value
        else:
            ok = getattr(facts, key) == value
        if not ok:
            return False
    return True


@dataclass(frozen=True)
class Classification:
    level: str
    reasons: tuple[str, ...]
    matched: bool


def classify(policy: Policy, facts: Facts) -> Classification:
    """The most severe level any rule gives. With no match, the least severe level, and it says so."""
    hits = [r for r in policy.rules if r.level in policy.level_names() and matches(r.when, facts)]
    if not hits:
        lowest = policy.levels[-1].name
        return Classification(lowest, ("no severity rule matched",), False)
    top = min(policy.rank(r.level) for r in hits)
    level = policy.levels[top].name
    return Classification(level, tuple(r.because for r in hits if r.level == level), True)


def effective_level(policy: Policy, incident: Incident, computed: str) -> str:
    """What the incident is run at: the more severe of what was declared and what the facts give."""
    if incident.declared_severity not in policy.level_names():
        return computed
    return min(incident.declared_severity, computed, key=policy.rank)


def applicable_obligations(policy: Policy, facts: Facts) -> list[Obligation]:
    return [o for o in policy.obligations if matches(o.when, facts)]


def due_at(declared_at: datetime, step: Step, level: str) -> datetime | None:
    """When a step is due at a severity, or None if it does not apply at that severity."""
    minutes = step.due.get(level)
    return None if minutes is None else declared_at + timedelta(minutes=minutes)


def applicable_ids(pb: Playbook, level: str, needed: set[str] | None = None) -> set[str]:
    """The steps that apply at a severity. A prerequisite that does not apply there is not waited for.

    A step that sends a notification applies only if that notification is needed for these facts,
    when `needed` (the ids of the obligations that apply) is given.
    """
    return {
        s.id
        for s in pb.steps
        if level in s.due and (needed is None or not s.notifies or s.notifies in needed)
    }


def first_event(incident: Incident, kind: str, step: str = "") -> Event | None:
    found = [e for e in incident.events if e.kind == kind and e.step == step and e.at is not None]
    return min(found, key=lambda e: e.at) if found else None  # type: ignore[arg-type, return-value]


@dataclass(frozen=True)
class StepState:
    step: Step
    status: str  # done, overdue, blocked, open
    due: datetime
    done_at: datetime | None
    late: bool


@dataclass(frozen=True)
class ObligationState:
    obligation: Obligation
    status: str  # done, overdue, open
    due: datetime
    done_at: datetime | None
    late: bool


@dataclass(frozen=True)
class Plan:
    incident: str
    computed: str
    declared: str
    level: str
    reasons: tuple[str, ...]
    steps: tuple[StepState, ...]
    obligations: tuple[ObligationState, ...]
    ack_due: datetime
    ack_done_at: datetime | None
    ack_overdue: bool
    update_due: datetime
    update_overdue: bool

    def overdue_steps(self) -> list[str]:
        return [s.step.id for s in self.steps if s.status == "overdue"]

    def overdue_obligations(self) -> list[str]:
        return [o.obligation.id for o in self.obligations if o.status == "overdue"]

    def done_steps(self) -> list[str]:
        return [s.step.id for s in self.steps if s.status == "done"]


def plan(
    lib: Library, incident: Incident, now: datetime, pb: Playbook | None = None
) -> Plan | None:
    """The state of an incident at `now`. None if the record has no times to plan from."""
    policy = lib.policy
    pb = pb or lib.playbooks.get(incident.playbook)
    if pb is None or incident.declared_at is None or incident.aware_at is None:
        return None
    cls = classify(policy, incident.facts)
    level = effective_level(policy, incident, cls.level)
    done_by_step: dict[str, Event] = {}
    for e in incident.events:
        if e.kind == "step" and e.at is not None:
            prior = done_by_step.get(e.step)
            if prior is None or (prior.at is not None and e.at < prior.at):
                done_by_step[e.step] = e
    steps = []
    needed = {o.id for o in applicable_obligations(policy, incident.facts)}
    here = applicable_ids(pb, level, needed)
    for s in pb.steps:
        due = due_at(incident.declared_at, s, level)
        if due is None or (s.notifies and s.notifies not in needed):
            continue
        ev = done_by_step.get(s.id)
        if ev is not None and ev.at is not None:
            steps.append(StepState(s, "done", due, ev.at, ev.at > due))
        elif now > due:
            steps.append(StepState(s, "overdue", due, None, True))
        elif any(r in here and r not in done_by_step for r in s.requires):
            steps.append(StepState(s, "blocked", due, None, False))
        else:
            steps.append(StepState(s, "open", due, None, False))
    notifier: dict[str, Event] = {}
    for s in pb.steps:
        ev = done_by_step.get(s.id)
        if s.notifies and ev is not None:
            prior = notifier.get(s.notifies)
            if prior is None or (prior.at is not None and ev.at is not None and ev.at < prior.at):
                notifier[s.notifies] = ev
    obligations = []
    for o in applicable_obligations(policy, incident.facts):
        start = incident.aware_at if o.clock_from == "aware" else incident.declared_at
        due = start + timedelta(hours=o.deadline_hours)
        ev = notifier.get(o.id)
        if ev is not None and ev.at is not None:
            obligations.append(ObligationState(o, "done", due, ev.at, ev.at > due))
        else:
            obligations.append(
                ObligationState(o, "overdue" if now > due else "open", due, None, now > due)
            )
    lv = policy.level(level)
    ack = first_event(incident, "ack")
    ack_due = incident.declared_at + timedelta(minutes=lv.ack_minutes)
    updates = [e.at for e in incident.events if e.kind == "update" and e.at is not None]
    last = max(updates) if updates else incident.declared_at
    update_due = last + timedelta(minutes=lv.update_minutes)
    closed = incident.status == "closed"
    return Plan(
        incident.id,
        cls.level,
        incident.declared_severity,
        level,
        cls.reasons,
        tuple(steps),
        tuple(obligations),
        ack_due,
        ack.at if ack else None,
        ack is None and now > ack_due and not closed,
        update_due,
        now > update_due and not closed,
    )


def run_drill(lib: Library, drill: Drill) -> list[str]:
    """Replay a scripted incident at its stated time and list where the plan differs from what was expected."""
    if drill.at is None:
        return ["the drill has no `at` time"]
    pl = plan(lib, drill.incident, drill.at)
    if pl is None:
        return ["the drill's incident cannot be planned (unknown playbook or missing times)"]
    e = drill.expect
    diffs = []
    if pl.level != e.severity:
        diffs.append(f"severity {pl.level}, expected {e.severity}")
    for name, got, want in (
        ("overdue steps", pl.overdue_steps(), e.overdue_steps),
        ("overdue notifications", pl.overdue_obligations(), e.overdue_obligations),
        ("done steps", pl.done_steps(), e.done_steps),
    ):
        if sorted(got) != sorted(want):
            diffs.append(f"{name} {sorted(got)}, expected {sorted(want)}")
    if pl.update_overdue != e.update_overdue:
        diffs.append(f"update overdue is {pl.update_overdue}, expected {e.update_overdue}")
    if pl.ack_overdue != e.ack_overdue:
        diffs.append(f"acknowledgement overdue is {pl.ack_overdue}, expected {e.ack_overdue}")
    return diffs
