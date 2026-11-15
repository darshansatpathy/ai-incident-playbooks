from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from playbooks.engine import (
    applicable_ids,
    applicable_obligations,
    classify,
    due_at,
    effective_level,
    first_event,
    matches,
    plan,
    run_drill,
)
from playbooks.model import Drill, Event, Expect, Facts
from tests.helpers import (
    AWARE,
    NOW,
    T0,
    at,
    event,
    incident,
    library,
    obligation,
    playbook,
    policy,
    step,
)

# --- matches and classify -----------------------------------------------------------------


def test_equality_membership_and_minimum_conditions() -> None:
    f = Facts(data_exposed="personal", ongoing=True, users_affected=100)
    assert matches({"ongoing": True}, f) and not matches({"ongoing": False}, f)
    assert matches({"data_exposed_in": ("personal", "internal")}, f)
    assert not matches({"data_exposed_in": ("none",)}, f)
    assert matches({"data_exposed": "personal"}, f)


@pytest.mark.parametrize(("users", "expected"), [(99, False), (100, True), (101, True)])
def test_minimum_is_inclusive(users: int, expected: bool) -> None:
    assert matches({"users_affected_min": 100}, Facts(users_affected=users)) is expected


def test_every_condition_must_hold_and_no_conditions_always_match() -> None:
    f = Facts(data_exposed="personal", ongoing=False)
    assert not matches({"data_exposed": "personal", "ongoing": True}, f)
    assert matches({}, f)


def test_the_most_severe_matching_level_wins_with_only_its_reasons() -> None:
    c = classify(policy(), Facts(harm="physical", data_exposed="personal"))
    assert (c.level, c.reasons, c.matched) == ("sev1", ("physical harm",), True)


def test_several_rules_at_the_same_level_all_explain_it() -> None:
    c = classify(policy(), Facts(data_exposed="personal", users_affected=500))
    assert c.level == "sev2" and c.reasons == ("personal data", "many people")


def test_with_no_match_the_least_severe_level_applies_and_says_so() -> None:
    c = classify(policy(), Facts())
    assert (c.level, c.reasons, c.matched) == ("sev3", ("no severity rule matched",), False)


def test_a_rule_for_an_unknown_level_is_ignored() -> None:
    from playbooks.model import SeverityRule

    p = policy(rules=(SeverityRule("sev0", "bogus", {}),))
    assert classify(p, Facts()).matched is False


def test_effective_level_is_the_more_severe_of_declared_and_computed() -> None:
    p = policy()
    inc = incident(declared_severity="sev3")
    assert effective_level(p, inc, "sev1") == "sev1"
    assert effective_level(p, incident(declared_severity="sev1"), "sev2") == "sev1"
    assert effective_level(p, incident(declared_severity="sev2"), "sev2") == "sev2"
    assert effective_level(p, incident(declared_severity="nonsense"), "sev2") == "sev2"


def test_obligations_apply_by_facts() -> None:
    p = policy()
    ids = lambda f: [o.id for o in applicable_obligations(p, f)]  # noqa: E731
    assert ids(Facts(data_exposed="personal")) == ["ob1"]
    assert ids(Facts(autonomous_action=True)) == ["ob2"]
    assert ids(Facts(data_exposed="personal", autonomous_action=True)) == ["ob1", "ob2"]
    assert ids(Facts()) == []


def test_due_at_is_declaration_plus_minutes_or_none() -> None:
    s = step("x", "detect", "sec", {"sev1": 10})
    assert due_at(T0, s, "sev1") == at(10)
    assert due_at(T0, s, "sev2") is None


def test_first_event_picks_the_earliest_and_ignores_undated_ones() -> None:
    inc = incident(
        event("", 30, kind="ack"),
        event("", 10, kind="ack"),
        Event(None, "ack", "", "p1", "", ""),
        event("", 5, kind="update"),
    )
    got = first_event(inc, "ack")
    assert got is not None and got.at == at(10)
    assert first_event(inc, "step") is None


def test_applicable_ids_follow_level_and_needed_notifications() -> None:
    pb = playbook()
    assert applicable_ids(pb, "sev3") == {"s-detect", "s-review"}
    assert applicable_ids(pb, "sev2") == {
        "s-detect",
        "s-contain",
        "s-notify",
        "s-review",
        "s-brief",
    }
    assert applicable_ids(pb, "sev2", set()) == {"s-detect", "s-contain", "s-review"}
    assert applicable_ids(pb, "sev2", {"ob1"}) == {"s-detect", "s-contain", "s-review", "s-notify"}


# --- plan: steps --------------------------------------------------------------------------


def state(pl, step_id: str):  # type: ignore[no-untyped-def]
    return next(s for s in pl.steps if s.step.id == step_id)


def test_a_step_is_open_until_due_then_overdue_with_the_boundary_exact() -> None:
    lib = library(incident())
    inc = lib.incidents["inc1"]
    due = at(30)  # s-detect at sev2
    on = plan(lib, inc, due)
    assert on is not None and state(on, "s-detect").status == "open"
    after = plan(lib, inc, due + timedelta(seconds=1))
    assert after is not None and state(after, "s-detect").status == "overdue"


def test_a_done_step_records_when_and_whether_it_was_late() -> None:
    lib = library(incident(event("s-detect", 30), event("s-contain", 61)))
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert pl is not None
    on_time, late = state(pl, "s-detect"), state(pl, "s-contain")
    assert (on_time.status, on_time.late, on_time.done_at) == ("done", False, at(30))
    assert (late.status, late.late) == ("done", True)


def test_a_step_waiting_on_an_unfinished_prerequisite_is_blocked_not_overdue_until_due() -> None:
    lib = library(incident())
    pl = plan(lib, lib.incidents["inc1"], at(5))
    assert pl is not None
    assert state(pl, "s-detect").status == "open"
    assert state(pl, "s-contain").status == "blocked"
    late = plan(lib, lib.incidents["inc1"], at(61))
    assert late is not None and state(late, "s-contain").status == "overdue"


def test_finishing_the_prerequisite_unblocks_the_step() -> None:
    lib = library(incident(event("s-detect", 5)))
    pl = plan(lib, lib.incidents["inc1"], at(6))
    assert pl is not None and state(pl, "s-contain").status == "open"


def test_a_prerequisite_that_does_not_apply_at_this_level_is_not_waited_for() -> None:
    lib = library(incident(declared_severity="sev3", facts=Facts()))
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None and pl.level == "sev3"
    assert [s.step.id for s in pl.steps] == ["s-detect", "s-review"]
    assert state(pl, "s-review").status == "open"


def test_steps_follow_the_level_the_incident_is_run_at_not_the_declared_one() -> None:
    lib = library(incident(declared_severity="sev3", facts=Facts(harm="physical")))
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None and (pl.level, pl.computed, pl.declared) == ("sev1", "sev1", "sev3")
    assert state(pl, "s-detect").due == at(10)


def test_a_notification_step_is_left_out_when_its_obligation_does_not_apply() -> None:
    lib = library(incident(facts=Facts(users_affected=500)))
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None and "s-notify" not in [s.step.id for s in pl.steps]
    assert pl.obligations == ()


def test_the_earliest_event_for_a_step_counts() -> None:
    lib = library(incident(event("s-detect", 50), event("s-detect", 10)))
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert (
        pl is not None
        and state(pl, "s-detect").done_at == at(10)
        and not state(pl, "s-detect").late
    )


def test_events_without_a_time_do_not_complete_anything() -> None:
    lib = library(incident(Event(None, "step", "s-detect", "p3", "", "x")))
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert pl is not None and state(pl, "s-detect").status == "overdue"


def test_plan_lists_overdue_and_done_steps_helpers() -> None:
    lib = library(incident(event("s-detect", 5)))
    pl = plan(lib, lib.incidents["inc1"], at(100))
    assert pl is not None
    assert pl.done_steps() == ["s-detect"]
    assert pl.overdue_steps() == ["s-contain"]


# --- plan: notifications ------------------------------------------------------------------


def test_the_notification_clock_starts_at_awareness_and_the_boundary_is_exact() -> None:
    lib = library(incident())
    inc = lib.incidents["inc1"]
    due = AWARE + timedelta(hours=48)
    on = plan(lib, inc, due)
    assert on is not None and on.obligations[0].status == "open" and on.obligations[0].due == due
    after = plan(lib, inc, due + timedelta(seconds=1))
    assert after is not None and after.obligations[0].status == "overdue"
    assert after.overdue_obligations() == ["ob1"]


def test_a_clock_can_start_at_declaration_instead() -> None:
    lib = library(incident(facts=Facts(autonomous_action=True)))
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None
    ob2 = next(o for o in pl.obligations if o.obligation.id == "ob2")
    assert ob2.due == T0 + timedelta(hours=4)


def test_the_step_that_notifies_satisfies_the_clock_and_late_is_recorded() -> None:
    lib = library(incident(event("s-notify", 10)))
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert pl is not None
    ob = pl.obligations[0]
    assert (ob.status, ob.late, ob.done_at) == ("done", False, at(10))
    after = AWARE + timedelta(hours=49)
    lib = library(incident(Event(after, "step", "s-notify", "p5", "", "x")))
    pl = plan(lib, lib.incidents["inc1"], after + timedelta(hours=1))
    assert pl is not None and (pl.obligations[0].status, pl.obligations[0].late) == ("done", True)


def test_a_notification_sent_exactly_at_the_deadline_is_not_late() -> None:
    due = AWARE + timedelta(hours=48)
    lib = library(incident(Event(due, "step", "s-notify", "p5", "", "x")))
    pl = plan(lib, lib.incidents["inc1"], due + timedelta(hours=1))
    assert pl is not None and (pl.obligations[0].status, pl.obligations[0].late) == ("done", False)


def test_a_different_step_does_not_satisfy_the_obligation() -> None:
    lib = library(incident(event("s-detect", 10)))
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert pl is not None and pl.obligations[0].status == "open"


def test_the_earliest_notifying_step_counts_when_two_steps_notify_the_same_obligation() -> None:
    extra = step("s-notify-2", "notify", "legal", {"sev2": 600}, notifies="ob1")
    pb = playbook((*playbook().steps, extra))
    lib = library(incident(event("s-notify", 300), event("s-notify-2", 100)), pbs=[pb])
    pl = plan(lib, lib.incidents["inc1"], NOW)
    assert pl is not None and pl.obligations[0].done_at == at(100)


# --- plan: acknowledgement and updates ----------------------------------------------------


def test_acknowledgement_is_overdue_only_after_its_deadline_and_only_if_missing() -> None:
    lib = library(incident())
    inc = lib.incidents["inc1"]
    ack_due = at(30)  # sev2
    on = plan(lib, inc, ack_due)
    after = plan(lib, inc, ack_due + timedelta(seconds=1))
    assert on is not None and not on.ack_overdue
    assert after is not None and after.ack_overdue and after.ack_due == ack_due
    acked = library(incident(event("", 10, "p1", "ack")))
    pl = plan(acked, acked.incidents["inc1"], NOW)
    assert pl is not None and not pl.ack_overdue and pl.ack_done_at == at(10)


def test_the_next_update_is_due_a_cadence_after_the_last_update_or_declaration() -> None:
    lib = library(incident())
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None and pl.update_due == at(120)
    lib = library(incident(event("", 50, "p1", "update"), event("", 20, "p1", "update")))
    pl = plan(lib, lib.incidents["inc1"], at(1))
    assert pl is not None and pl.update_due == at(170)


def test_update_overdue_boundary() -> None:
    lib = library(incident())
    inc = lib.incidents["inc1"]
    assert not plan(lib, inc, at(120)).update_overdue  # type: ignore[union-attr]
    assert plan(lib, inc, at(120) + timedelta(seconds=1)).update_overdue  # type: ignore[union-attr]


def test_a_closed_incident_has_no_overdue_acknowledgement_or_update() -> None:
    lib = library(incident(status="closed"))
    pl = plan(lib, lib.incidents["inc1"], NOW + timedelta(days=30))
    assert pl is not None and not pl.ack_overdue and not pl.update_overdue


def test_plan_needs_a_playbook_and_times() -> None:
    lib = library(incident(playbook="nope"))
    assert plan(lib, lib.incidents["inc1"], NOW) is None
    assert plan(library(incident(declared_at=None)), incident(declared_at=None), NOW) is None
    assert plan(library(incident(aware_at=None)), incident(aware_at=None), NOW) is None


def test_plan_can_be_given_a_playbook_directly() -> None:
    lib = library(incident(playbook="other"))
    assert plan(lib, lib.incidents["inc1"], NOW, playbook()) is not None


# --- drills -------------------------------------------------------------------------------


def drill(expect: Expect, *events: Event, at_minutes: float = 100) -> Drill:
    return Drill(incident(*events), at(at_minutes), "", expect)


GOOD = Expect("sev2", ("s-contain",), (), ("s-detect",), False, True)


def test_a_drill_that_matches_its_expectation_has_no_differences() -> None:
    d = drill(replace(GOOD, update_overdue=False), event("s-detect", 5))
    assert run_drill(library(), d) == []


def test_each_kind_of_difference_is_named() -> None:
    lib = library()
    ev = event("s-detect", 5)
    assert (
        "severity sev2, expected sev1"
        in run_drill(lib, drill(replace(GOOD, severity="sev1"), ev))[0]
    )
    assert any(
        "overdue steps" in d for d in run_drill(lib, drill(replace(GOOD, overdue_steps=()), ev))
    )
    assert any(
        "overdue notifications" in d
        for d in run_drill(lib, drill(replace(GOOD, overdue_obligations=("ob1",)), ev))
    )
    assert any("done steps" in d for d in run_drill(lib, drill(replace(GOOD, done_steps=()), ev)))
    assert any(
        "update overdue" in d for d in run_drill(lib, drill(replace(GOOD, update_overdue=True), ev))
    )
    assert any(
        "acknowledgement overdue" in d
        for d in run_drill(lib, drill(replace(GOOD, ack_overdue=False), ev))
    )


def test_a_drill_without_a_time_or_a_playbook_cannot_run() -> None:
    lib = library()
    assert run_drill(lib, Drill(incident(), None, "", GOOD)) == ["the drill has no `at` time"]
    bad = Drill(incident(playbook="nope"), at(1), "", GOOD)
    assert "cannot be planned" in run_drill(lib, bad)[0]


def test_order_does_not_matter_in_a_drill_expectation() -> None:
    lib = library(incident())
    d = drill(Expect("sev2", ("s-detect", "s-contain"), (), (), False, True), at_minutes=100)
    assert run_drill(lib, d) == []
    d2 = drill(Expect("sev2", ("s-contain", "s-detect"), (), (), False, True), at_minutes=100)
    assert run_drill(lib, d2) == []
    assert obligation().id == "ob1"
