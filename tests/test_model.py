from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from playbooks.model import (
    Facts,
    load_drills,
    load_incidents,
    load_library,
    load_playbooks,
    load_policy,
)
from tests.helpers import ROOT

POLICY = """
phases = ["detect", "contain"]
required_phases = ["contain"]
kinds = ["k"]

[contain_within_minutes]
sev1 = 30

[[levels]]
name = "sev1"
ack_minutes = 15
update_minutes = 60

[[severity_rules]]
level = "sev1"
because = "b"
when = { data_exposed_in = ["personal"], users_affected_min = 5, ongoing = true }

[roles.a]
final = true

[people.p]
roles = ["a"]

[[obligations]]
id = "o"
kind = "internal"
audience = "x"
clock_from = "declared"
deadline_hours = 1
"""

PLAYBOOK = """
id = "pb"
title = "T"
applies_to = ["k"]

[[steps]]
id = "s"
phase = "detect"
role = "a"
action = "do"
due = { sev1 = 10 }
"""

INCIDENT = """
id = "i1"
title = "T"
kind = "k"
playbook = "pb"
declared_at = 2026-11-15T10:00:00Z
aware_at = 2026-11-15T09:30:00+01:00
declared_severity = "sev1"

[facts]
data_exposed = "personal"
users_affected = 7

[[events]]
at = 2026-11-15T10:05:00Z
kind = "ack"
by = "p"

[[events]]
at = 2026-11-15T10:06:00Z
step = "s"
by = "p"
evidence = "e"
"""


def write(path: Path, name: str, text: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_text(text, encoding="utf-8")
    return path


def test_the_example_loads_without_problems() -> None:
    lib, problems = load_library(ROOT)
    assert problems == [] and lib is not None
    assert len(lib.playbooks) == 5 and len(lib.incidents) == 3 and len(lib.drills) == 3
    assert lib.policy.level_names() == ("sev1", "sev2", "sev3", "sev4")


def test_policy_loads_every_part(tmp_path: Path) -> None:
    p, problems = load_policy(write(tmp_path, "policy.toml", POLICY))
    assert problems == [] and p is not None
    assert p.level("sev1").ack_minutes == 15 and p.rank("sev1") == 0
    assert p.contain_within == {"sev1": 30}
    assert p.rules[0].when == {
        "data_exposed_in": ("personal",),
        "users_affected_min": 5,
        "ongoing": True,
    }
    assert p.roles["a"].final and p.people["p"] == ("a",)
    assert p.obligations[0].example is False and p.obligations[0].source == ""


def test_policy_reports_bad_conditions(tmp_path: Path) -> None:
    def problems_for(when: str) -> list[str]:
        text = POLICY.replace(
            'when = { data_exposed_in = ["personal"], users_affected_min = 5, ongoing = true }',
            f"when = {{ {when} }}",
        )
        return load_policy(write(tmp_path / str(abs(hash(when))), "policy.toml", text))[1]

    assert any("not a condition on a known fact" in p for p in problems_for("colour = 1"))
    assert any("non-empty list" in p for p in problems_for('data_exposed_in = ["lunar"]'))
    assert any("non-empty list" in p for p in problems_for("data_exposed_in = []"))
    assert any("non-empty list" in p for p in problems_for("ongoing_in = [true]"))
    assert any("whole number" in p for p in problems_for('users_affected_min = "many"'))
    assert any("whole number" in p for p in problems_for("ongoing_min = 1"))
    assert any("whole number" in p for p in problems_for("users_affected_min = true"))
    assert any("does not take" in p for p in problems_for('data_exposed = "lunar"'))
    assert any("does not take" in p for p in problems_for('ongoing = "yes"'))
    assert problems_for('harm = "financial"') == []
    assert problems_for("ongoing = false") == []


def test_policy_missing_broken_and_incomplete(tmp_path: Path) -> None:
    none, problems = load_policy(tmp_path)
    assert none is None and "missing" in problems[0]
    none, problems = load_policy(write(tmp_path / "b", "policy.toml", "not = = toml"))
    assert none is None and problems
    none, problems = load_policy(
        write(tmp_path / "c", "policy.toml", POLICY.replace('kinds = ["k"]', ""))
    )
    assert none is None and any("`kinds`" in p for p in problems)


def test_playbook_loads_with_defaults(tmp_path: Path) -> None:
    pbs, problems = load_playbooks(write(tmp_path, "pb.toml", PLAYBOOK))
    assert problems == []
    s = pbs["pb"].steps[0]
    assert (s.evidence, s.notifies, s.requires, s.due) == ("none", "", (), {"sev1": 10})
    assert pbs["pb"].file_stem == "pb" and pbs["pb"].step("s") is s and pbs["pb"].step("x") is None


def test_playbook_problems(tmp_path: Path) -> None:
    _, problems = load_playbooks(
        write(tmp_path, "a.toml", PLAYBOOK.replace("sev1 = 10", 'sev1 = "soon"'))
    )
    assert any("whole numbers of minutes" in p for p in problems)
    write(tmp_path / "c", "a.toml", PLAYBOOK)
    write(tmp_path / "c", "b.toml", PLAYBOOK)
    _, problems = load_playbooks(tmp_path / "c")
    assert any("already used" in p for p in problems)
    _, problems = load_playbooks(tmp_path / "nowhere")
    assert "no such directory" in problems[0]
    _, problems = load_playbooks(write(tmp_path / "d", "a.toml", "= ="))
    assert problems


def test_incident_loads_times_facts_and_events(tmp_path: Path) -> None:
    incs, problems = load_incidents(write(tmp_path, "i1.toml", INCIDENT))
    assert problems == []
    inc = incs["i1"]
    assert inc.declared_at == datetime(2026, 11, 15, 10, tzinfo=UTC)
    assert inc.aware_at is not None and inc.aware_at.utcoffset() is not None
    assert inc.status == "open" and inc.file_stem == "i1"
    assert inc.facts == Facts(data_exposed="personal", users_affected=7)
    assert [e.kind for e in inc.events] == ["ack", "step"]
    assert inc.events[0].step == "" and inc.events[1].evidence == "e"


def test_times_must_say_their_offset(tmp_path: Path) -> None:
    naive = INCIDENT.replace(
        "declared_at = 2026-11-15T10:00:00Z", "declared_at = 2026-11-15T10:00:00"
    )
    _, problems = load_incidents(write(tmp_path, "i1.toml", naive))
    assert any("with an offset" in p for p in problems)
    date_only = INCIDENT.replace("declared_at = 2026-11-15T10:00:00Z", "declared_at = 2026-11-15")
    _, problems = load_incidents(write(tmp_path / "b", "i1.toml", date_only))
    assert any("with an offset" in p for p in problems)
    bad_event = INCIDENT.replace("at = 2026-11-15T10:05:00Z", 'at = "yesterday"')
    _, problems = load_incidents(write(tmp_path / "c", "i1.toml", bad_event))
    assert any("events[1]" in p and "offset" in p for p in problems)


def test_facts_are_validated(tmp_path: Path) -> None:
    _, p = load_incidents(
        write(
            tmp_path,
            "i1.toml",
            INCIDENT.replace('data_exposed = "personal"', 'data_exposed = "lunar"'),
        )
    )
    assert any("data_exposed" in x for x in p)
    _, p = load_incidents(
        write(tmp_path / "b", "i1.toml", INCIDENT.replace("users_affected = 7", "colour = 1"))
    )
    assert any("unknown fact `colour`" in x for x in p)
    _, p = load_incidents(
        write(tmp_path / "c", "i1.toml", INCIDENT.replace("users_affected = 7", "ongoing = 3"))
    )
    assert any("`ongoing`" in x for x in p)


def test_a_step_event_needs_a_step_but_other_events_do_not(tmp_path: Path) -> None:
    text = INCIDENT.replace('step = "s"\n', "")
    _, problems = load_incidents(write(tmp_path, "i1.toml", text))
    assert any("`step` must be a non-empty string" in p for p in problems)


def test_incidents_missing_directory_is_empty_and_broken_toml_is_reported(tmp_path: Path) -> None:
    assert load_incidents(tmp_path / "nope") == ({}, [])
    _, problems = load_incidents(write(tmp_path, "a.toml", "= ="))
    assert problems and "incidents/a.toml" in problems[0]


def test_drill_loads_expectations(tmp_path: Path) -> None:
    text = INCIDENT.replace(
        "declared_severity", 'at = 2026-11-15T11:00:00Z\nnote = "n"\ndeclared_severity', 1
    ) + (
        '\n[expect]\nseverity = "sev1"\noverdue_steps = ["a"]\n'
        'done_steps = ["s"]\nupdate_overdue = true\n'
    )
    drills, problems = load_drills(write(tmp_path, "d.toml", text))
    assert problems == []
    d = drills["i1"]
    assert d.at == datetime(2026, 11, 15, 11, tzinfo=UTC) and d.note == "n"
    assert (d.expect.severity, d.expect.overdue_steps, d.expect.done_steps) == (
        "sev1",
        ("a",),
        ("s",),
    )
    assert (
        d.expect.update_overdue and not d.expect.ack_overdue and d.expect.overdue_obligations == ()
    )
    assert load_drills(tmp_path / "nope") == ({}, [])
    _, problems = load_drills(write(tmp_path / "b", "d.toml", "= ="))
    assert problems and "drills/d.toml" in problems[0]
    _, problems = load_drills(write(tmp_path / "c", "d.toml", INCIDENT))
    assert any("`at`" in p for p in problems) and any("`severity`" in p for p in problems)


def test_library_is_none_when_anything_is_wrong(tmp_path: Path) -> None:
    lib, problems = load_library(tmp_path)
    assert lib is None and problems
