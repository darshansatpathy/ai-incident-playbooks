from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from playbooks import rules
from playbooks.model import Event, Facts, Level, Role, SeverityRule
from playbooks.rules import can_act, role_chain
from tests.helpers import (
    AWARE,
    NOW,
    ROOT,
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


def clean_incident(**kw: object):  # type: ignore[no-untyped-def]
    return incident(
        event("", 10, "p1", "ack"),
        event("s-detect", 5, "p3"),
        event("s-contain", 20, "p2"),
        event("s-notify", 100, "p5"),
        event("s-review", 200, "p1"),
        status="closed",
        **kw,
    )


def found(lib, rule: str, subject: str | None = None, now=NOW):  # type: ignore[no-untyped-def]
    return [f for f in rules.run(lib, now) if f.rule == rule and subject in (None, f.subject)]


def messages(lib, rule: str, now=NOW) -> str:  # type: ignore[no-untyped-def]
    return " | ".join(f.message for f in found(lib, rule, now=now))


def test_a_clean_library_has_no_findings() -> None:
    assert rules.run(library(clean_incident()), NOW) == []


def test_the_example_has_only_the_expected_findings() -> None:
    from playbooks.model import load_library

    lib, problems = load_library(ROOT)
    assert lib is not None and problems == []
    got = sorted(
        (f.rule, f.severity, f.subject)
        for f in rules.run(lib, T0.replace(year=2026, month=11, day=15, hour=12))
    )
    assert [g for g in got if g[0] != "AIP010"] == [
        ("AIP015", "medium", "inc-2026-002"),
        ("AIP015", "medium", "inc-2026-002"),
    ]
    assert {g[2] for g in got if g[0] == "AIP010"} == {
        "ob-regulator-a",
        "ob-affected-people",
        "ob-sector-regulator",
    }


def test_every_rule_has_a_triggering_case() -> None:
    bad_roles = dict(policy().roles)
    bad_roles["eng"] = Role("eng", "", False)
    triggers = {
        "AIP001": library(pol=policy(levels=())),
        "AIP002": library(pbs=[playbook(file_stem="other")]),
        "AIP003": library(pbs=[playbook((step("a", "detect", "ghost", {"sev1": 5}),))]),
        "AIP004": library(pbs=[playbook((step("a", "detect", "sec", {"sev1": 5}),))]),
        "AIP005": library(pol=policy(contain_within={"sev1": 5})),
        "AIP006": library(pol=policy(roles=bad_roles)),
        "AIP007": library(pol=policy(people={})),
        "AIP008": library(pol=policy(kinds=("data_exposure", "vendor_outage"))),
        "AIP009": library(pol=policy(obligations=(obligation(deadline_hours=0),))),
        "AIP010": library(
            pol=policy(obligations=(obligation(source=""), obligation("ob2", kind="internal")))
        ),
        "AIP011": library(pol=policy(obligations=(obligation(), obligation("ob9")))),
        "AIP012": library(incident(kind="nonsense")),
        "AIP013": library(incident(event("s-detect", 5, "p1"), event("s-contain", 20, "p2"))),
        "AIP014": library(incident(declared_severity="sev3", facts=Facts(data_exposed="personal"))),
        "AIP015": library(incident()),
        "AIP016": library(incident(status="closed")),
    }
    assert set(triggers) == {r.id for r in rules.REGISTRY}
    for rule, lib in triggers.items():
        assert found(lib, rule), f"{rule} did not fire on its own trigger"


def test_rule_ids_are_unique_and_documented() -> None:
    ids = [r.id for r in rules.REGISTRY]
    assert ids == sorted(set(ids)) and all(r.why and r.title for r in rules.REGISTRY)
    assert all(r.severity in rules.LEVELS for r in rules.REGISTRY)


def test_findings_are_sorted_most_severe_first() -> None:
    lib = library(incident(), pol=policy(obligations=(obligation(example=True),)))
    ranks = [rules.level_rank(f.severity) for f in rules.run(lib, NOW)]
    assert ranks == sorted(ranks, reverse=True) and len(set(ranks)) > 1


# role helpers ---------------------------------------------------------------------------------


def test_role_chain_follows_backups_and_stops_at_loops_and_unknown_roles() -> None:
    p = policy()
    assert role_chain(p, "ic") == ["ic", "eng", "sec", "exec"]
    assert role_chain(p, "ghost") == []
    loop = policy(roles={"a": Role("a", "b", False), "b": Role("b", "a", False)})
    assert role_chain(loop, "a") == ["a", "b"]


def test_can_act_includes_backups_but_not_juniors() -> None:
    p = policy()
    assert can_act(p, "p1", "ic") and can_act(p, "p4", "ic") and can_act(p, "p3", "eng")
    assert not can_act(p, "p1", "sec") and not can_act(p, "nobody", "ic")


# AIP001 -------------------------------------------------------------------------------------


def test_aip001_checks_levels_phases_kinds_and_rules() -> None:
    assert "no severity levels" in messages(library(pol=policy(levels=())), "AIP001")
    dup = (Level("a", 1, 1), Level("a", 1, 1))
    assert "not unique" in messages(library(pol=policy(levels=dup)), "AIP001")
    assert "needs positive ack_minutes" in messages(
        library(pol=policy(levels=(Level("a", 0, 5),))), "AIP001"
    )
    assert "needs positive ack_minutes" in messages(
        library(pol=policy(levels=(Level("a", 5, 0),))), "AIP001"
    )
    assert "needs positive ack_minutes" not in messages(
        library(pol=policy(levels=(Level("a", 1, 1),))), "AIP001"
    )
    assert "non-empty list" in messages(library(pol=policy(phases=())), "AIP001")
    assert "required phase `x`" in messages(library(pol=policy(required_phases=("x",))), "AIP001")
    assert "no incident kinds" in messages(library(pol=policy(kinds=())), "AIP001")
    bad_rule = (SeverityRule("sev9", "x", {}),)
    assert "unknown level `sev9`" in messages(library(pol=policy(rules=bad_rule)), "AIP001")
    assert "contain_within_minutes" in messages(
        library(pol=policy(contain_within={"sev9": 5})), "AIP001"
    )
    assert "contain_within_minutes" in messages(
        library(pol=policy(contain_within={"sev1": 0})), "AIP001"
    )
    assert not found(library(), "AIP001")


# AIP002 -------------------------------------------------------------------------------------


def test_aip002_checks_playbook_shape() -> None:
    assert "file name must be the id" in messages(library(pbs=[playbook(file_stem="z")]), "AIP002")
    assert "unknown incident kind" in messages(library(pbs=[playbook(applies_to=("x",))]), "AIP002")
    assert "applies to no incident kind" in messages(
        library(pbs=[playbook(applies_to=())]), "AIP002"
    )
    empty = replace(playbook(), steps=())
    assert "has no steps" in messages(library(pbs=[empty]), "AIP002")
    twice = playbook(
        (step("a", "detect", "sec", {"sev1": 5}), step("a", "detect", "sec", {"sev1": 5}))
    )
    assert "`a` is used more than once" in messages(library(pbs=[twice]), "AIP002")
    assert "unknown phase" in messages(
        library(pbs=[playbook((step("a", "panic", "sec", {"sev1": 5}),))]), "AIP002"
    )
    assert "never applies" in messages(
        library(pbs=[playbook((step("a", "detect", "sec", {}),))]), "AIP002"
    )
    assert "known level" in messages(
        library(pbs=[playbook((step("a", "detect", "sec", {"sev9": 5}),))]), "AIP002"
    )
    assert "positive minutes" in messages(
        library(pbs=[playbook((step("a", "detect", "sec", {"sev1": 0}),))]), "AIP002"
    )
    odd = replace(step("a", "detect", "sec", {"sev1": 5}), evidence="vibes")
    assert "evidence `vibes`" in messages(library(pbs=[playbook((odd,))]), "AIP002")


# AIP003 -------------------------------------------------------------------------------------


def test_aip003_roles_prerequisites_cycles_and_order() -> None:
    assert "unknown role `ghost`" in messages(
        library(pbs=[playbook((step("a", "detect", "ghost", {"sev1": 5}),))]), "AIP003"
    )
    assert "requires unknown step `zzz`" in messages(
        library(pbs=[playbook((step("a", "detect", "sec", {"sev1": 5}, "zzz"),))]), "AIP003"
    )
    cyc = playbook(
        (step("a", "detect", "sec", {"sev1": 5}, "b"), step("b", "detect", "sec", {"sev1": 5}, "a"))
    )
    got = messages(library(pbs=[cyc]), "AIP003")
    assert "`a` is part of a requires cycle" in got and "`b` is part of a requires cycle" in got
    selfref = playbook((step("a", "detect", "sec", {"sev1": 5}, "a"),))
    assert "cycle" in messages(library(pbs=[selfref]), "AIP003")
    longer = playbook(
        (
            step("a", "detect", "sec", {"sev1": 5}, "b"),
            step("b", "detect", "sec", {"sev1": 5}, "c"),
            step("c", "detect", "sec", {"sev1": 5}, "a"),
        )
    )
    assert messages(library(pbs=[longer]), "AIP003").count("cycle") == 3


def test_aip003_a_prerequisite_due_later_is_flagged_but_equal_is_fine() -> None:
    first = step("a", "detect", "sec", {"sev1": 10})
    later = playbook((first, step("b", "contain", "eng", {"sev1": 9}, "a")))
    equal = playbook((first, step("b", "contain", "eng", {"sev1": 10}, "a")))
    assert "due at sev1 before `a`" in messages(library(pbs=[later]), "AIP003")
    assert "before `a`" not in messages(library(pbs=[equal]), "AIP003")
    other_level = playbook((first, step("b", "contain", "eng", {"sev2": 1}, "a")))
    assert "before" not in messages(library(pbs=[other_level]), "AIP003")


# AIP004 / AIP005 ----------------------------------------------------------------------------


def test_aip004_required_phases_must_apply_at_the_most_severe_level() -> None:
    only_low = playbook(
        (step("a", "contain", "eng", {"sev2": 5}), step("b", "review", "ic", {"sev1": 5}))
    )
    assert "no `contain` step that applies at sev1" in messages(library(pbs=[only_low]), "AIP004")
    assert not found(library(), "AIP004")


def test_aip005_containment_must_exist_and_be_fast_enough() -> None:
    slow = playbook(
        (
            step("a", "contain", "eng", {"sev1": 31, "sev2": 90}),
            step("r", "review", "ic", {"sev1": 5}),
        )
    )
    assert "first containment at sev1 is due in 31 minutes; the policy allows 30" in messages(
        library(pbs=[slow]), "AIP005"
    )
    exact = playbook((step("a", "contain", "eng", {"sev1": 30, "sev2": 90}),))
    assert not found(library(pbs=[exact]), "AIP005")
    none_at_sev2 = playbook((step("a", "contain", "eng", {"sev1": 30}),))
    assert "no containment step at sev2" in messages(library(pbs=[none_at_sev2]), "AIP005")
    two = playbook(
        (
            step("a", "contain", "eng", {"sev1": 99, "sev2": 90}),
            step("b", "contain", "eng", {"sev1": 10, "sev2": 90}),
        )
    )
    assert not found(library(pbs=[two]), "AIP005")


# AIP006 / AIP007 ----------------------------------------------------------------------------


def test_aip006_every_role_needs_cover() -> None:
    roles = dict(policy().roles)
    assert not found(library(), "AIP006")
    roles["eng"] = Role("eng", "", False)
    assert "no backup and is not marked final" in messages(
        library(pol=policy(roles=roles)), "AIP006"
    )
    roles["eng"] = Role("eng", "ghost", False)
    assert "`ghost` is not a role" in messages(library(pol=policy(roles=roles)), "AIP006")
    roles["exec"] = Role("exec", "ic", True)
    roles["eng"] = Role("eng", "sec", False)
    assert "is marked final but has a backup" in messages(
        library(pol=policy(roles=roles)), "AIP006"
    )
    loop = {"a": Role("a", "b", False), "b": Role("b", "a", False)}
    assert "backups loop" in messages(library(pol=policy(roles=loop)), "AIP006")


def test_aip007_people_and_unfillable_roles() -> None:
    assert "holds unknown role `ghost`" in messages(
        library(pol=policy(people={"x": ("ghost",)})), "AIP007"
    )
    lonely = {"p4": ("exec",)}  # only the final role is held; everyone's backups end there
    assert not found(library(pol=policy(people=lonely)), "AIP007")
    nobody = {"p1": ("ic",)}
    assert "nobody can act for it" in messages(library(pol=policy(people=nobody)), "AIP007")
    assert not found(library(), "AIP007")


# AIP008 - AIP011 ----------------------------------------------------------------------------


def test_aip008_every_kind_needs_a_playbook() -> None:
    f = found(library(pol=policy(kinds=("data_exposure", "vendor_outage"))), "AIP008")
    assert [x.subject for x in f] == ["vendor_outage"]


def test_aip009_obligation_fields() -> None:
    def msg(**kw: object) -> str:
        return messages(library(pol=policy(obligations=(obligation(**kw),))), "AIP009")

    assert "deadline_hours must be positive" in msg(deadline_hours=0)
    assert "deadline_hours must be positive" in msg(deadline_hours=-1)
    assert not msg(deadline_hours=1)
    assert "kind `moral`" in msg(kind="moral")
    assert "clock_from `never`" in msg(clock_from="never")
    dup = policy(obligations=(obligation(), obligation()))
    assert "used more than once" in messages(library(pol=dup), "AIP009")


def test_aip010_legal_deadlines_are_reviewed_or_marked_placeholders() -> None:
    def f(**kw: object):  # type: ignore[no-untyped-def]
        return found(library(pol=policy(obligations=(obligation(**kw),))), "AIP010")

    assert not f()
    for missing in ("source", "reviewed_by", "reviewed_on"):
        got = f(**{missing: " "})
        assert got and got[0].severity == "high", missing
    placeholder = f(example=True, source="", reviewed_by="", reviewed_on="")
    assert placeholder and placeholder[0].severity == "low"
    assert not f(kind="internal", source="", reviewed_by="", reviewed_on="")


def test_aip011_obligations_and_steps_must_match() -> None:
    unreachable = policy(
        obligations=(obligation(), obligation("ob2", kind="internal"), obligation("ob3"))
    )
    assert "no playbook step notifies it" in messages(library(pol=unreachable), "AIP011")
    unknown = playbook((*playbook().steps, step("z", "notify", "ic", {"sev1": 5}, notifies="ob9")))
    assert "notifies unknown obligation `ob9`" in messages(library(pbs=[unknown]), "AIP011")
    assert not found(library(), "AIP011")


# AIP012 / AIP013 ----------------------------------------------------------------------------


def test_aip012_checks_the_incident_record() -> None:
    def msg(*events: Event, **kw: object) -> str:
        return messages(library(incident(*events, **kw)), "AIP012")

    assert "file named" in msg(file_stem="x")
    assert "kind `bogus`" in msg(kind="bogus")
    assert "playbook `nope` does not exist" in msg(playbook="nope")
    other = playbook(applies_to=())
    assert "does not apply to kind" in messages(
        library(
            incident(),
            pbs=[replace(other, applies_to=("vendor_outage",))],
            pol=policy(kinds=("data_exposure", "vendor_outage")),
        ),
        "AIP012",
    )
    assert "declared severity `sev9`" in msg(declared_severity="sev9")
    assert "status `paused`" in msg(status="paused")
    assert "declared before the organisation was aware" in msg(aware_at=T0 + timedelta(minutes=1))
    assert not found(library(incident(aware_at=T0)), "AIP012")
    assert "dated before awareness" in msg(
        Event(AWARE - timedelta(seconds=1), "step", "s-detect", "p3", "", "")
    )
    assert "dated before awareness" not in msg(Event(AWARE, "step", "s-detect", "p3", "", ""))
    assert "who is not a known person" in msg(event("s-detect", 5, "stranger"))
    assert "not in `pb1`" in msg(event("s-nope", 5, "p3"))
    assert "recorded more than once" in msg(event("s-detect", 5, "p3"), event("s-detect", 6, "p3"))
    assert "event has kind `shout`" in msg(event("", 5, "p3", "shout"))


def test_aip012_a_step_that_needs_evidence_must_have_some() -> None:
    needs = replace(playbook().steps[0], evidence="ticket")
    pb = playbook((needs, *playbook().steps[1:]))
    without = library(incident(event("s-detect", 5, "p3", evidence="  ")), pbs=[pb])
    assert "needs ticket evidence and has none" in messages(without, "AIP012")
    with_it = library(incident(event("s-detect", 5, "p3", evidence="TICKET-1")), pbs=[pb])
    assert "needs ticket" not in messages(with_it, "AIP012")


def test_aip013_the_right_person_in_the_right_order() -> None:
    wrong = library(incident(event("s-detect", 5, "p1")))
    assert "`p1`, who does not hold `sec` or its backup" in messages(wrong, "AIP013")
    backup_ok = library(incident(event("s-detect", 5, "p4")))
    assert "does not hold" not in messages(backup_ok, "AIP013")
    stranger = library(incident(event("s-detect", 5, "stranger")))
    assert not found(stranger, "AIP013")  # reported by AIP012 instead
    early = library(incident(event("s-contain", 5, "p2"), event("s-detect", 10, "p3")))
    assert "`s-contain` was done before `s-detect`" in messages(early, "AIP013")
    same_time = library(incident(event("s-contain", 10, "p2"), event("s-detect", 10, "p3")))
    assert not found(same_time, "AIP013")
    never = library(incident(event("s-contain", 10, "p2")))
    assert "was done before `s-detect`" in messages(never, "AIP013")


def test_aip013_ignores_prerequisites_that_do_not_apply_at_this_level() -> None:
    lib = library(incident(event("s-review", 10, "p1"), declared_severity="sev3", facts=Facts()))
    assert not found(lib, "AIP013")


def test_aip013_skips_incidents_with_no_playbook() -> None:
    assert not found(library(incident(playbook="nope")), "AIP013")


# AIP014 ------------------------------------------------------------------------------------


def test_aip014_understating_is_high_and_overstating_is_low() -> None:
    under = found(
        library(incident(declared_severity="sev3", facts=Facts(harm="physical"))), "AIP014"
    )
    assert (
        under[0].severity == "high" and "declared sev3 but the facts give sev1" in under[0].message
    )
    over = found(
        library(incident(declared_severity="sev1", facts=Facts(data_exposed="personal"))), "AIP014"
    )
    assert over[0].severity == "low"
    assert not found(
        library(incident(declared_severity="sev2", facts=Facts(data_exposed="personal"))), "AIP014"
    )
    assert not found(library(incident(declared_severity="nonsense")), "AIP014")


# AIP015 / AIP016 ----------------------------------------------------------------------------


def test_aip015_open_incidents_are_checked_for_overdue_work() -> None:
    lib = library(incident())
    got = messages(lib, "AIP015", at(121))
    assert (
        "step `s-detect` was due" in got
        and "not acknowledged by" in got
        and "an update was due" in got
    )
    assert "notification `ob1`" not in got
    late = AWARE + timedelta(hours=48, seconds=1)
    assert "notification `ob1` was due" in messages(lib, "AIP015", late)
    assert (
        next(f for f in found(lib, "AIP015", now=late) if "notification" in f.message).severity
        == "high"
    )
    closed = library(incident(status="closed"))
    assert not found(closed, "AIP015")
    assert not found(library(incident(playbook="nope")), "AIP015")


def test_aip015_nothing_is_overdue_exactly_on_time() -> None:
    lib = library(incident(event("", 5, "p1", "ack")))
    assert "step `s-detect`" not in messages(lib, "AIP015", at(30))
    assert "an update" not in messages(lib, "AIP015", at(120))


def test_aip016_a_closed_incident_must_be_complete() -> None:
    assert "steps not done: s-detect" in messages(library(incident(status="closed")), "AIP016")
    assert "notifications not sent: ob1" in messages(library(incident(status="closed")), "AIP016")
    assert not found(library(clean_incident()), "AIP016")
    assert not found(library(incident()), "AIP016")
    assert not found(library(incident(status="closed", playbook="nope")), "AIP016")


@pytest.mark.parametrize("missing", ["s-detect", "s-contain", "s-notify", "s-review"])
def test_aip016_each_missing_step_is_reported(missing: str) -> None:
    done = {
        "s-detect": ("p3", 5),
        "s-contain": ("p2", 20),
        "s-notify": ("p5", 100),
        "s-review": ("p1", 200),
    }
    events = [event(s, m, p) for s, (p, m) in done.items() if s != missing]
    lib = library(incident(*events, status="closed"))
    assert missing in messages(lib, "AIP016")
