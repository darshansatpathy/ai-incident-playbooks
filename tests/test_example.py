"""The checked-in example: what it contains is pinned, and what is committed is what the code produces."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from playbooks.cli import REPORTS, _reports
from playbooks.engine import plan, run_drill
from playbooks.model import Library, load_library
from tests.helpers import ROOT

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def lib() -> Library:
    loaded, problems = load_library(ROOT)
    assert loaded is not None and problems == []
    return loaded


def test_committed_reports_are_current(lib: Library) -> None:
    for name, text in _reports(lib, NOW).items():
        assert (ROOT / "reports" / name).read_text(encoding="utf-8") == text, name
    assert set(REPORTS) == {p.name for p in (ROOT / "reports").iterdir()}


def test_every_drill_passes(lib: Library) -> None:
    for name, drill in lib.drills.items():
        assert run_drill(lib, drill) == [], name


def test_every_drill_is_sensitive_to_its_expectation(lib: Library) -> None:
    """A drill that still passes when its expectation is wrong would prove nothing."""
    from dataclasses import replace

    for name, drill in lib.drills.items():
        wrong = replace(
            drill,
            expect=replace(
                drill.expect, severity="sev4" if drill.expect.severity != "sev4" else "sev1"
            ),
        )
        assert run_drill(lib, wrong), name
        wrong = replace(
            drill,
            expect=replace(drill.expect, done_steps=(*drill.expect.done_steps, "no-such-step")),
        )
        assert run_drill(lib, wrong), name


def test_every_kind_has_a_playbook_and_every_obligation_has_a_step(lib: Library) -> None:
    for kind in lib.policy.kinds:
        assert any(kind in pb.applies_to for pb in lib.playbooks.values()), kind
    notified = {s.notifies for pb in lib.playbooks.values() for s in pb.steps if s.notifies}
    assert {o.id for o in lib.policy.obligations} <= notified


def test_the_example_incidents_are_where_they_are_described_to_be(lib: Library) -> None:
    p1 = plan(lib, lib.incidents["inc-2026-001"], NOW)
    p2 = plan(lib, lib.incidents["inc-2026-002"], NOW)
    p3 = plan(lib, lib.incidents["inc-2026-003"], NOW)
    assert p1 and p2 and p3
    assert (
        p1.level == "sev2" and not p1.overdue_steps() and all(s.status == "done" for s in p1.steps)
    )
    assert p2.level == "sev1" and p2.overdue_steps() == ["assess-permissions"] and p2.update_overdue
    assert p3.level == "sev3" and not p3.overdue_steps() and not p3.update_overdue


def test_every_legal_deadline_in_the_example_is_a_placeholder(lib: Library) -> None:
    legal = [o for o in lib.policy.obligations if o.kind == "legal"]
    assert legal and all(o.example for o in legal)
    assert all(not o.reviewed_by for o in legal)


def test_the_policy_report_says_it_is_not_legal_advice(lib: Library) -> None:
    text = (ROOT / "reports" / "policy.md").read_text(encoding="utf-8")
    assert "not legal advice" in text and "PLACEHOLDER" in text


def test_every_person_in_the_example_is_synthetic(lib: Library) -> None:
    assert set(lib.policy.people) == {f"person-{c}" for c in "abcdef"}
