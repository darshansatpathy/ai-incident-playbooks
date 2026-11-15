"""Lint rules AIP001 to AIP016: problems in the policy, playbooks and incident records."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from playbooks.engine import (
    applicable_ids,
    applicable_obligations,
    classify,
    effective_level,
    plan,
)
from playbooks.model import (
    CLOCKS,
    EVENT_KINDS,
    EVIDENCE_KINDS,
    OBLIGATION_KINDS,
    STATUSES,
    Incident,
    Library,
    Playbook,
    Policy,
)

LEVELS = ("low", "medium", "high")


def level_rank(level: str) -> int:
    return LEVELS.index(level)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    subject: str
    message: str


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    why: str
    check: Callable[[Library, datetime], list[Finding]]


def role_chain(policy: Policy, role: str) -> list[str]:
    """The role and the backups behind it, in order, stopping at a repeat."""
    chain: list[str] = []
    current = role
    while current and current in policy.roles and current not in chain:
        chain.append(current)
        current = policy.roles[current].backup
    return chain


def can_act(policy: Policy, person: str, role: str) -> bool:
    return bool(set(policy.people.get(person, ())) & set(role_chain(policy, role)))


def _pbs(lib: Library) -> list[Playbook]:
    return [lib.playbooks[k] for k in sorted(lib.playbooks)]


def _incs(lib: Library) -> list[Incident]:
    return [lib.incidents[k] for k in sorted(lib.incidents)]


def aip001(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []

    def add(m: str) -> None:
        out.append(Finding("AIP001", "high", "policy", m))

    names = p.level_names()
    if not names:
        add("no severity levels are defined")
    if len(set(names)) != len(names):
        add("severity level names are not unique")
    for lv in p.levels:
        if lv.ack_minutes <= 0 or lv.update_minutes <= 0:
            add(f"level `{lv.name}` needs positive ack_minutes and update_minutes")
    if not p.phases or len(set(p.phases)) != len(p.phases):
        add("phases must be a non-empty list without repeats")
    for ph in p.required_phases:
        if ph not in p.phases:
            add(f"required phase `{ph}` is not one of the phases")
    if not p.kinds:
        add("no incident kinds are defined")
    for r in p.rules:
        if r.level not in names:
            add(f"a severity rule refers to unknown level `{r.level}`")
    for lv_name, minutes in p.contain_within.items():
        if lv_name not in names or minutes <= 0:
            add(f"contain_within_minutes `{lv_name}` must be a known level and a positive number")
    return out


def aip002(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for pb in _pbs(lib):

        def add(m: str, pb: Playbook = pb) -> None:
            out.append(Finding("AIP002", "high", pb.id, m))

        if pb.file_stem != pb.id:
            add(f"is in a file named {pb.file_stem}.toml; the file name must be the id")
        for k in pb.applies_to:
            if k not in p.kinds:
                add(f"applies to unknown incident kind `{k}`")
        if not pb.applies_to:
            add("applies to no incident kind")
        if not pb.steps:
            add("has no steps")
        ids = [s.id for s in pb.steps]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            add(f"step id `{dup}` is used more than once")
        for s in pb.steps:
            if s.phase not in p.phases:
                add(f"step `{s.id}` has unknown phase `{s.phase}`")
            if s.evidence not in EVIDENCE_KINDS:
                add(
                    f"step `{s.id}` evidence `{s.evidence}` is not one of {', '.join(EVIDENCE_KINDS)}"
                )
            if not s.due:
                add(f"step `{s.id}` is due at no severity, so it never applies")
            for lv_name, minutes in s.due.items():
                if lv_name not in p.level_names() or minutes <= 0:
                    add(f"step `{s.id}` due `{lv_name}` must be a known level and positive minutes")
    return out


def _cycle(pb: Playbook) -> list[str]:
    graph = {s.id: s.requires for s in pb.steps}
    bad: list[str] = []
    for start in graph:
        seen: set[str] = set()
        stack = list(graph[start])
        while stack:
            cur = stack.pop()
            if cur == start:
                bad.append(start)
                break
            if cur in seen or cur not in graph:
                continue
            seen.add(cur)
            stack.extend(graph[cur])
    return bad


def aip003(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for pb in _pbs(lib):
        for s in pb.steps:
            if s.role not in p.roles:
                out.append(
                    Finding("AIP003", "high", pb.id, f"step `{s.id}` names unknown role `{s.role}`")
                )
            for r in s.requires:
                prior = pb.step(r)
                if prior is None:
                    out.append(
                        Finding(
                            "AIP003", "high", pb.id, f"step `{s.id}` requires unknown step `{r}`"
                        )
                    )
                    continue
                for lv_name, minutes in s.due.items():
                    if lv_name in prior.due and prior.due[lv_name] > minutes:
                        out.append(
                            Finding(
                                "AIP003",
                                "medium",
                                pb.id,
                                f"step `{s.id}` is due at {lv_name} before `{r}`, which it requires",
                            )
                        )
        for sid in _cycle(pb):
            out.append(
                Finding("AIP003", "high", pb.id, f"step `{sid}` is part of a requires cycle")
            )
    return out


def aip004(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    top = p.levels[0].name if p.levels else ""
    for pb in _pbs(lib):
        for phase in p.required_phases:
            if not any(s.phase == phase and top in s.due for s in pb.steps):
                out.append(
                    Finding("AIP004", "high", pb.id, f"has no `{phase}` step that applies at {top}")
                )
    return out


def aip005(lib: Library, now: datetime) -> list[Finding]:
    out = []
    for pb in _pbs(lib):
        for lv_name, limit in sorted(lib.policy.contain_within.items()):
            times = [s.due[lv_name] for s in pb.steps if s.phase == "contain" and lv_name in s.due]
            if not times:
                out.append(
                    Finding("AIP005", "high", pb.id, f"has no containment step at {lv_name}")
                )
            elif min(times) > limit:
                out.append(
                    Finding(
                        "AIP005",
                        "high",
                        pb.id,
                        f"first containment at {lv_name} is due in {min(times)} minutes; the policy allows {limit}",
                    )
                )
    return out


def aip006(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for name in sorted(p.roles):
        role = p.roles[name]
        if role.backup and role.backup not in p.roles:
            out.append(Finding("AIP006", "high", name, f"backup `{role.backup}` is not a role"))
        elif not role.backup and not role.final:
            out.append(Finding("AIP006", "high", name, "has no backup and is not marked final"))
        elif role.backup and role.final:
            out.append(Finding("AIP006", "medium", name, "is marked final but has a backup"))
        chain = role_chain(p, name)
        if role.backup and chain and p.roles[chain[-1]].backup in chain:
            out.append(Finding("AIP006", "high", name, f"backups loop: {' -> '.join(chain)}"))
    return out


def aip007(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for person, roles in sorted(p.people.items()):
        for r in roles:
            if r not in p.roles:
                out.append(Finding("AIP007", "high", person, f"holds unknown role `{r}`"))
    used = {s.role for pb in _pbs(lib) for s in pb.steps if s.role in p.roles}
    for role in sorted(used):
        if not any(can_act(p, person, role) for person in p.people):
            out.append(
                Finding(
                    "AIP007",
                    "high",
                    role,
                    "is needed by a playbook step and nobody can act for it, even through a backup",
                )
            )
    return out


def aip008(lib: Library, now: datetime) -> list[Finding]:
    return [
        Finding("AIP008", "high", k, "has no playbook")
        for k in lib.policy.kinds
        if not any(k in pb.applies_to for pb in _pbs(lib))
    ]


def aip009(lib: Library, now: datetime) -> list[Finding]:
    out, seen = [], set()
    for o in lib.policy.obligations:
        if o.id in seen:
            out.append(Finding("AIP009", "high", o.id, "id is used more than once"))
        seen.add(o.id)
        if o.kind not in OBLIGATION_KINDS:
            out.append(
                Finding(
                    "AIP009",
                    "high",
                    o.id,
                    f"kind `{o.kind}` is not one of {', '.join(OBLIGATION_KINDS)}",
                )
            )
        if o.clock_from not in CLOCKS:
            out.append(
                Finding(
                    "AIP009",
                    "high",
                    o.id,
                    f"clock_from `{o.clock_from}` is not one of {', '.join(CLOCKS)}",
                )
            )
        if o.deadline_hours <= 0:
            out.append(Finding("AIP009", "high", o.id, "deadline_hours must be positive"))
    return out


def aip010(lib: Library, now: datetime) -> list[Finding]:
    """No legal deadline is trusted until a named person has reviewed it; placeholders say so."""
    out = []
    for o in lib.policy.obligations:
        if o.kind != "legal":
            continue
        if o.example:
            out.append(
                Finding(
                    "AIP010",
                    "low",
                    o.id,
                    "is a placeholder deadline; set and review it with your legal team",
                )
            )
        elif not (o.source.strip() and o.reviewed_by.strip() and o.reviewed_on.strip()):
            out.append(
                Finding(
                    "AIP010",
                    "high",
                    o.id,
                    "is a legal obligation without a source, a reviewer and a review date",
                )
            )
    return out


def aip011(lib: Library, now: datetime) -> list[Finding]:
    out = []
    ids = {o.id for o in lib.policy.obligations}
    notified = {s.notifies for pb in _pbs(lib) for s in pb.steps if s.notifies}
    for o in lib.policy.obligations:
        if o.id not in notified:
            out.append(
                Finding(
                    "AIP011",
                    "high",
                    o.id,
                    "no playbook step notifies it, so nothing would ever satisfy its clock",
                )
            )
    for pb in _pbs(lib):
        for s in pb.steps:
            if s.notifies and s.notifies not in ids:
                out.append(
                    Finding(
                        "AIP011",
                        "high",
                        pb.id,
                        f"step `{s.id}` notifies unknown obligation `{s.notifies}`",
                    )
                )
    return out


def aip012(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for inc in _incs(lib):

        def add(m: str, inc: Incident = inc) -> None:
            out.append(Finding("AIP012", "high", inc.id, m))

        pb = lib.playbooks.get(inc.playbook)
        if inc.file_stem != inc.id:
            add(f"is in a file named {inc.file_stem}.toml; the file name must be the id")
        if inc.kind not in p.kinds:
            add(f"kind `{inc.kind}` is not one of {', '.join(p.kinds)}")
        if pb is None:
            add(f"playbook `{inc.playbook}` does not exist")
        elif inc.kind not in pb.applies_to:
            add(f"playbook `{pb.id}` does not apply to kind `{inc.kind}`")
        if inc.declared_severity not in p.level_names():
            add(
                f"declared severity `{inc.declared_severity}` is not one of {', '.join(p.level_names())}"
            )
        if inc.status not in STATUSES:
            add(f"status `{inc.status}` is not one of {', '.join(STATUSES)}")
        if inc.aware_at and inc.declared_at and inc.aware_at > inc.declared_at:
            add("was declared before the organisation was aware of it")
        seen: set[str] = set()
        for e in inc.events:
            if e.kind not in EVENT_KINDS:
                add(f"an event has kind `{e.kind}`, not one of {', '.join(EVENT_KINDS)}")
            if e.at and inc.aware_at and e.at < inc.aware_at:
                add(f"an event for `{e.step or e.kind}` is dated before awareness")
            if e.by not in p.people:
                add(f"an event for `{e.step or e.kind}` is by `{e.by}`, who is not a known person")
            if e.kind != "step":
                continue
            step = pb.step(e.step) if pb else None
            if pb and step is None:
                add(f"an event is for step `{e.step}`, which is not in `{pb.id}`")
            if e.step in seen:
                add(f"step `{e.step}` is recorded more than once")
            seen.add(e.step)
            if step and step.evidence != "none" and not e.evidence.strip():
                add(f"step `{step.id}` needs {step.evidence} evidence and has none")
    return out


def aip013(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for inc in _incs(lib):
        pb = lib.playbooks.get(inc.playbook)
        if pb is None:
            continue
        done = {e.step: e for e in inc.events if e.kind == "step" and e.at}
        level = effective_level(p, inc, classify(p, inc.facts).level)
        needed = {o.id for o in applicable_obligations(p, inc.facts)}
        here = applicable_ids(pb, level, needed)
        for e in inc.events:
            step = pb.step(e.step) if e.kind == "step" else None
            if step is None:
                continue
            if e.by in p.people and step.role in p.roles and not can_act(p, e.by, step.role):
                out.append(
                    Finding(
                        "AIP013",
                        "high",
                        inc.id,
                        f"`{e.step}` was done by `{e.by}`, who does not hold `{step.role}` or its backup",
                    )
                )
            for r in step.requires:
                if r not in here:
                    continue
                prior = done.get(r)
                if prior is None or (prior.at and e.at and prior.at > e.at):
                    out.append(
                        Finding(
                            "AIP013",
                            "high",
                            inc.id,
                            f"`{e.step}` was done before `{r}`, which it requires",
                        )
                    )
    return out


def aip014(lib: Library, now: datetime) -> list[Finding]:
    p, out = lib.policy, []
    for inc in _incs(lib):
        if inc.declared_severity not in p.level_names():
            continue
        computed = classify(p, inc.facts).level
        if p.rank(inc.declared_severity) > p.rank(computed):
            out.append(
                Finding(
                    "AIP014",
                    "high",
                    inc.id,
                    f"declared {inc.declared_severity} but the facts give {computed}; it is run at {computed}",
                )
            )
        elif p.rank(inc.declared_severity) < p.rank(computed):
            out.append(
                Finding(
                    "AIP014",
                    "low",
                    inc.id,
                    f"declared {inc.declared_severity}, above the {computed} the facts give; that is allowed",
                )
            )
    return out


def aip015(lib: Library, now: datetime) -> list[Finding]:
    out = []
    for inc in _incs(lib):
        if inc.status != "open":
            continue
        pl = plan(lib, inc, now)
        if pl is None:
            continue
        for o in pl.obligations:
            if o.status == "overdue":
                out.append(
                    Finding(
                        "AIP015",
                        "high",
                        inc.id,
                        f"notification `{o.obligation.id}` was due {o.due.isoformat()}",
                    )
                )
        for s in pl.steps:
            if s.status == "overdue":
                out.append(
                    Finding(
                        "AIP015",
                        "medium",
                        inc.id,
                        f"step `{s.step.id}` was due {s.due.isoformat()}",
                    )
                )
        if pl.ack_overdue:
            out.append(
                Finding("AIP015", "medium", inc.id, f"not acknowledged by {pl.ack_due.isoformat()}")
            )
        if pl.update_overdue:
            out.append(
                Finding(
                    "AIP015", "medium", inc.id, f"an update was due {pl.update_due.isoformat()}"
                )
            )
    return out


def aip016(lib: Library, now: datetime) -> list[Finding]:
    out = []
    for inc in _incs(lib):
        if inc.status != "closed":
            continue
        pl = plan(lib, inc, now)
        if pl is None:
            continue
        open_steps = [s.step.id for s in pl.steps if s.status != "done"]
        if open_steps:
            out.append(
                Finding(
                    "AIP016",
                    "high",
                    inc.id,
                    f"is closed with steps not done: {', '.join(open_steps)}",
                )
            )
        open_ob = [o.obligation.id for o in pl.obligations if o.status != "done"]
        if open_ob:
            out.append(
                Finding(
                    "AIP016",
                    "high",
                    inc.id,
                    f"is closed with notifications not sent: {', '.join(open_ob)}",
                )
            )
    return out


REGISTRY: tuple[Rule, ...] = (
    Rule(
        "AIP001",
        "high",
        "Policy is well formed",
        "Levels, phases and kinds that do not add up make every plan wrong.",
        aip001,
    ),
    Rule(
        "AIP002",
        "high",
        "Playbooks are well formed",
        "A step with an unknown phase or no deadline silently drops out of the plan.",
        aip002,
    ),
    Rule(
        "AIP003",
        "high",
        "Step roles and prerequisites are valid and acyclic",
        "A step nobody owns, or that waits for itself, never gets done.",
        aip003,
    ),
    Rule(
        "AIP004",
        "high",
        "Playbooks contain, and review",
        "A playbook that does not stop the harm or learn from it is a diary.",
        aip004,
    ),
    Rule(
        "AIP005",
        "high",
        "Containment is as fast as the policy requires",
        "Slow containment at the top severities is the cost the policy exists to cap.",
        aip005,
    ),
    Rule(
        "AIP006",
        "high",
        "Every role has a backup",
        "People are unavailable; a role without cover stalls the incident.",
        aip006,
    ),
    Rule(
        "AIP007",
        "high",
        "Every needed role can be filled",
        "A role nobody holds is a step nobody does.",
        aip007,
    ),
    Rule(
        "AIP008",
        "high",
        "Every incident kind has a playbook",
        "An incident with no playbook is improvised.",
        aip008,
    ),
    Rule(
        "AIP009",
        "high",
        "Obligations are well formed",
        "A notification clock with a bad start or length is wrong at the worst time.",
        aip009,
    ),
    Rule(
        "AIP010",
        "high",
        "Legal deadlines are reviewed or marked placeholders",
        "A deadline nobody reviewed is a guess that looks like a requirement.",
        aip010,
    ),
    Rule(
        "AIP011",
        "high",
        "Obligations and the steps that satisfy them match",
        "An obligation no step satisfies is an alarm that can never be cleared.",
        aip011,
    ),
    Rule(
        "AIP012",
        "high",
        "Incident records are well formed",
        "A record with wrong references cannot be planned or audited.",
        aip012,
    ),
    Rule(
        "AIP013",
        "high",
        "Steps are done by the right person, in order",
        "An action by someone without the role, or before its prerequisite, is not the action the playbook meant.",
        aip013,
    ),
    Rule(
        "AIP014",
        "high",
        "Severity is not understated",
        "Declaring a lower severity than the facts give hides the incident from the response it needs.",
        aip014,
    ),
    Rule(
        "AIP015",
        "high",
        "Nothing open is overdue",
        "An overdue notification or containment step is the finding that matters most.",
        aip015,
    ),
    Rule(
        "AIP016",
        "high",
        "Closed incidents are complete",
        "Closing with steps or notifications outstanding hides unfinished work.",
        aip016,
    ),
)


def run(lib: Library, now: datetime) -> list[Finding]:
    out: list[Finding] = []
    for r in REGISTRY:
        out.extend(r.check(lib, now))
    return sorted(out, key=lambda f: (-level_rank(f.severity), f.rule, f.subject, f.message))
