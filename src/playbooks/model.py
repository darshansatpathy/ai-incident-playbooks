"""Policy, playbooks and incident records, loaded from TOML."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from playbooks._toml import Reader

DATA_VALUES = ("none", "internal", "personal", "confidential")
HARM_VALUES = ("none", "reputational", "financial", "physical")
BOOL_FACTS = ("customer_facing", "autonomous_action", "ongoing", "regulated_domain")
ENUM_FACTS = {"data_exposed": DATA_VALUES, "harm": HARM_VALUES}
INT_FACTS = ("users_affected",)
FACT_NAMES = (*ENUM_FACTS, *BOOL_FACTS, *INT_FACTS)
STATUSES = ("open", "closed")
EVENT_KINDS = ("step", "update", "ack")
EVIDENCE_KINDS = ("none", "ticket", "log", "link", "text")
CLOCKS = ("aware", "declared")
OBLIGATION_KINDS = ("legal", "internal")


@dataclass(frozen=True)
class Facts:
    data_exposed: str = "none"
    harm: str = "none"
    customer_facing: bool = False
    autonomous_action: bool = False
    ongoing: bool = False
    regulated_domain: bool = False
    users_affected: int = 0


@dataclass(frozen=True)
class Level:
    name: str
    ack_minutes: int
    update_minutes: int


@dataclass(frozen=True)
class SeverityRule:
    level: str
    because: str
    when: dict[str, Any]


@dataclass(frozen=True)
class Role:
    name: str
    backup: str
    final: bool


@dataclass(frozen=True)
class Obligation:
    id: str
    kind: str
    audience: str
    when: dict[str, Any]
    clock_from: str
    deadline_hours: int
    example: bool
    source: str
    reviewed_by: str
    reviewed_on: str


@dataclass(frozen=True)
class Policy:
    phases: tuple[str, ...]
    required_phases: tuple[str, ...]
    contain_within: dict[str, int]
    kinds: tuple[str, ...]
    levels: tuple[Level, ...]
    rules: tuple[SeverityRule, ...]
    roles: dict[str, Role]
    people: dict[str, tuple[str, ...]]
    obligations: tuple[Obligation, ...]

    def level_names(self) -> tuple[str, ...]:
        return tuple(lv.name for lv in self.levels)

    def level(self, name: str) -> Level:
        return next(lv for lv in self.levels if lv.name == name)

    def rank(self, name: str) -> int:
        """Lower is more severe: the first level is the worst."""
        return self.level_names().index(name)


@dataclass(frozen=True)
class Step:
    id: str
    phase: str
    role: str
    action: str
    due: dict[str, int]
    requires: tuple[str, ...]
    evidence: str
    notifies: str


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    applies_to: tuple[str, ...]
    steps: tuple[Step, ...]
    file_stem: str = ""

    def step(self, step_id: str) -> Step | None:
        return next((s for s in self.steps if s.id == step_id), None)


@dataclass(frozen=True)
class Event:
    at: datetime | None
    kind: str
    step: str
    by: str
    note: str
    evidence: str


@dataclass(frozen=True)
class Incident:
    id: str
    title: str
    kind: str
    playbook: str
    declared_at: datetime | None
    aware_at: datetime | None
    declared_severity: str
    status: str
    facts: Facts
    events: tuple[Event, ...]
    file_stem: str = ""


@dataclass(frozen=True)
class Expect:
    severity: str
    overdue_steps: tuple[str, ...]
    overdue_obligations: tuple[str, ...]
    done_steps: tuple[str, ...]
    update_overdue: bool
    ack_overdue: bool


@dataclass(frozen=True)
class Drill:
    incident: Incident
    at: datetime | None
    note: str
    expect: Expect


@dataclass(frozen=True)
class Library:
    policy: Policy
    playbooks: dict[str, Playbook]
    incidents: dict[str, Incident]
    drills: dict[str, Drill] = field(default_factory=dict)


def _toml(path: Path, r: Reader) -> dict[str, Any] | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        r.problems.append(f"{r.source}: {exc}")
        return None


def _when(r: Reader, raw: Any, where: str) -> dict[str, Any]:
    """Conditions on facts: `fact = value`, `fact_in = [...]` or `fact_min = n`."""
    t = r.table(raw, where)
    out: dict[str, Any] = {}
    for key, value in t.items():
        base = key.removesuffix("_in").removesuffix("_min")
        if base not in FACT_NAMES:
            r.bad(where, f"`{key}` is not a condition on a known fact ({', '.join(FACT_NAMES)})")
            continue
        if key.endswith("_in"):
            ok = isinstance(value, list) and value and all(isinstance(v, str) for v in value)
            allowed = ENUM_FACTS.get(base)
            if not ok or allowed is None or any(v not in allowed for v in value):
                r.bad(where, f"`{key}` must be a non-empty list from {allowed}")
                continue
            out[key] = tuple(value)
        elif key.endswith("_min"):
            if base not in INT_FACTS or isinstance(value, bool) or not isinstance(value, int):
                r.bad(where, f"`{key}` must be a whole number, on a numeric fact")
                continue
            out[key] = value
        elif (base in BOOL_FACTS and isinstance(value, bool)) or (
            base in ENUM_FACTS and value in ENUM_FACTS[base]
        ):
            out[key] = value
        else:
            r.bad(where, f"`{key}` has a value that fact does not take")
    return out


def load_policy(directory: Path) -> tuple[Policy | None, list[str]]:
    path = directory / "policy.toml"
    r = Reader("policy/policy.toml")
    if not path.is_file():
        return None, [f"{path}: missing"]
    data = _toml(path, r)
    if data is None:
        return None, r.problems
    levels = []
    for i, raw in enumerate(data.get("levels", [])):
        w = f" levels[{i + 1}]"
        t = r.table(raw, w)
        levels.append(
            Level(
                r.string(t, "name", w),
                r.integer(t, "ack_minutes", w),
                r.integer(t, "update_minutes", w),
            )
        )
    rules = []
    for i, raw in enumerate(data.get("severity_rules", [])):
        w = f" severity_rules[{i + 1}]"
        t = r.table(raw, w)
        rules.append(
            SeverityRule(
                r.string(t, "level", w), r.string(t, "because", w), _when(r, t.get("when", {}), w)
            )
        )
    roles = {}
    for name, raw in r.table(data.get("roles", {}), " roles").items():
        w = f" roles.{name}"
        t = r.table(raw, w)
        roles[name] = Role(
            name,
            r.string(t, "backup", w, allow_empty=True),
            r.boolean(t, "final", w, default=False),
        )
    people = {}
    for pid, raw in r.table(data.get("people", {}), " people").items():
        people[pid] = r.strings(r.table(raw, f" people.{pid}"), "roles", f" people.{pid}")
    obligations = []
    for i, raw in enumerate(data.get("obligations", [])):
        w = f" obligations[{i + 1}]"
        t = r.table(raw, w)
        obligations.append(
            Obligation(
                r.string(t, "id", w),
                r.string(t, "kind", w),
                r.string(t, "audience", w),
                _when(r, t.get("when", {}), w),
                r.string(t, "clock_from", w),
                r.integer(t, "deadline_hours", w),
                r.boolean(t, "example", w, default=False),
                r.string(t, "source", w, allow_empty=True),
                r.string(t, "reviewed_by", w, allow_empty=True),
                r.string(t, "reviewed_on", w, allow_empty=True),
            )
        )
    contain = {
        k: v
        for k, v in r.table(
            data.get("contain_within_minutes", {}), " contain_within_minutes"
        ).items()
        if isinstance(v, int) and not isinstance(v, bool)
    }
    policy = Policy(
        r.strings(data, "phases", ""),
        r.strings(data, "required_phases", ""),
        contain,
        r.strings(data, "kinds", ""),
        tuple(levels),
        tuple(rules),
        roles,
        people,
        tuple(obligations),
    )
    return (policy if not r.problems else None), r.problems


def load_playbooks(directory: Path) -> tuple[dict[str, Playbook], list[str]]:
    out: dict[str, Playbook] = {}
    problems: list[str] = []
    if not directory.is_dir():
        return out, [f"{directory}: no such directory"]
    for path in sorted(directory.glob("*.toml")):
        r = Reader(f"playbooks/{path.name}")
        data = _toml(path, r)
        if data is None:
            problems.extend(r.problems)
            continue
        steps = []
        for i, raw in enumerate(data.get("steps", [])):
            w = f" steps[{i + 1}]"
            t = r.table(raw, w)
            due_raw = r.table(t.get("due", {}), w + ".due")
            due = {
                k: v for k, v in due_raw.items() if isinstance(v, int) and not isinstance(v, bool)
            }
            if len(due) != len(due_raw):
                r.bad(w, "`due` values must be whole numbers of minutes")
            steps.append(
                Step(
                    r.string(t, "id", w),
                    r.string(t, "phase", w),
                    r.string(t, "role", w),
                    r.string(t, "action", w),
                    due,
                    r.strings(t, "requires", w, default=[]),
                    r.string(t, "evidence", w) if "evidence" in t else "none",
                    r.string(t, "notifies", w, allow_empty=True) if "notifies" in t else "",
                )
            )
        pb = Playbook(
            r.string(data, "id", ""),
            r.string(data, "title", ""),
            r.strings(data, "applies_to", ""),
            tuple(steps),
            path.stem,
        )
        if pb.id in out:
            r.bad("", f"id `{pb.id}` is already used")
        out[pb.id] = pb
        problems.extend(r.problems)
    return out, problems


def parse_facts(r: Reader, raw: Any, where: str) -> Facts:
    t = r.table(raw, where)
    for key in t:
        if key not in FACT_NAMES:
            r.bad(where, f"unknown fact `{key}`")
    base = Facts()
    values: dict[str, Any] = {}
    for name, allowed in ENUM_FACTS.items():
        v = t.get(name, getattr(base, name))
        if v not in allowed:
            r.bad(where, f"`{name}` must be one of {', '.join(allowed)}")
            v = getattr(base, name)
        values[name] = v
    for name in BOOL_FACTS:
        values[name] = r.boolean(t, name, where, default=False)
    values["users_affected"] = r.integer(t, "users_affected", where, default=0)
    return Facts(**values)


def parse_incident(r: Reader, data: dict[str, Any], stem: str) -> Incident:
    events = []
    for i, raw in enumerate(data.get("events", [])):
        w = f" events[{i + 1}]"
        t = r.table(raw, w)
        kind = r.string(t, "kind", w) if "kind" in t else "step"
        events.append(
            Event(
                r.moment(t, "at", w),
                kind,
                r.string(t, "step", w, allow_empty=kind != "step"),
                r.string(t, "by", w),
                r.string(t, "note", w, allow_empty=True) if "note" in t else "",
                r.string(t, "evidence", w, allow_empty=True) if "evidence" in t else "",
            )
        )
    return Incident(
        r.string(data, "id", ""),
        r.string(data, "title", ""),
        r.string(data, "kind", ""),
        r.string(data, "playbook", ""),
        r.moment(data, "declared_at", ""),
        r.moment(data, "aware_at", ""),
        r.string(data, "declared_severity", ""),
        r.string(data, "status", "") if "status" in data else "open",
        parse_facts(r, data.get("facts", {}), ".facts"),
        tuple(events),
        stem,
    )


def load_incidents(directory: Path) -> tuple[dict[str, Incident], list[str]]:
    out: dict[str, Incident] = {}
    problems: list[str] = []
    if not directory.is_dir():
        return out, []
    for path in sorted(directory.glob("*.toml")):
        r = Reader(f"incidents/{path.name}")
        data = _toml(path, r)
        if data is None:
            problems.extend(r.problems)
            continue
        inc = parse_incident(r, data, path.stem)
        out[inc.id or path.stem] = inc
        problems.extend(r.problems)
    return out, problems


def load_drills(directory: Path) -> tuple[dict[str, Drill], list[str]]:
    out: dict[str, Drill] = {}
    problems: list[str] = []
    if not directory.is_dir():
        return out, []
    for path in sorted(directory.glob("*.toml")):
        r = Reader(f"drills/{path.name}")
        data = _toml(path, r)
        if data is None:
            problems.extend(r.problems)
            continue
        inc = parse_incident(r, data, path.stem)
        e = r.table(data.get("expect", {}), ".expect")
        expect = Expect(
            r.string(e, "severity", ".expect"),
            r.strings(e, "overdue_steps", ".expect", default=[]),
            r.strings(e, "overdue_obligations", ".expect", default=[]),
            r.strings(e, "done_steps", ".expect", default=[]),
            r.boolean(e, "update_overdue", ".expect", default=False),
            r.boolean(e, "ack_overdue", ".expect", default=False),
        )
        out[inc.id or path.stem] = Drill(
            inc, r.moment(data, "at", ""), r.string(data, "note", "", allow_empty=True), expect
        )
        problems.extend(r.problems)
    return out, problems


def load_library(root: Path) -> tuple[Library | None, list[str]]:
    policy, p1 = load_policy(root / "policy")
    pbs, p2 = load_playbooks(root / "playbooks")
    incs, p3 = load_incidents(root / "incidents")
    drills, p4 = load_drills(root / "drills")
    problems = [*p1, *p2, *p3, *p4]
    if policy is None or problems:
        return None, problems
    return Library(policy, pbs, incs, drills), problems
