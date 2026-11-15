"""Command line: lint, classify, plan, drill, report, rules."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from playbooks import __version__, render, rules
from playbooks.engine import applicable_obligations, classify, plan, run_drill
from playbooks.model import BOOL_FACTS, DATA_VALUES, HARM_VALUES, Facts, Library, load_library

REPORTS = (
    "policy.md",
    "playbooks.md",
    "coverage.md",
    "incidents.md",
    "drills.md",
    "lint.md",
    "rules.md",
)


def _load(root: Path) -> Library | None:
    lib, problems = load_library(root)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    return None if lib is None or problems else lib


def _now(a: argparse.Namespace) -> datetime | None:
    try:
        d = datetime.fromisoformat(a.now.replace("Z", "+00:00"))
    except ValueError:
        d = None
    if d is None or d.tzinfo is None:
        print(
            f"error: --now `{a.now}` is not a date and time with an offset, like 2026-11-15T12:00:00Z",
            file=sys.stderr,
        )
        return None
    return d


def cmd_lint(a: argparse.Namespace) -> int:
    lib, now = _load(Path(a.root)), _now(a)
    if lib is None or now is None:
        return 2
    findings = rules.run(lib, now)
    if a.format == "markdown":
        print(render.findings_markdown(findings), end="")
    elif a.format == "json":
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():8} {f.rule} {f.subject}: {f.message}")
        print(
            f"{len(lib.playbooks)} playbooks, {len(lib.incidents)} incidents, {len(rules.REGISTRY)} rules: {len(findings)} findings"
        )
    threshold = rules.level_rank(a.fail_on)
    return 1 if any(rules.level_rank(f.severity) >= threshold for f in findings) else 0


def cmd_classify(a: argparse.Namespace) -> int:
    lib = _load(Path(a.root))
    if lib is None:
        return 2
    facts = Facts(
        a.data_exposed,
        a.harm,
        a.customer_facing,
        a.autonomous_action,
        a.ongoing,
        a.regulated_domain,
        a.users_affected,
    )
    c = classify(lib.policy, facts)
    print(f"severity: {c.level}")
    print("because:")
    for r in c.reasons:
        print(f"  - {r}")
    obs = applicable_obligations(lib.policy, facts)
    print("notification clocks that would start:")
    for o in obs:
        flag = " (placeholder)" if o.example else ""
        print(f"  - {o.id}: {o.audience}, {o.deadline_hours} hours from {o.clock_from}{flag}")
    if not obs:
        print("  none")
    print(f"\n{render.NOT_LEGAL_ADVICE}")
    return 0


def cmd_plan(a: argparse.Namespace) -> int:
    lib, now = _load(Path(a.root)), _now(a)
    if lib is None or now is None:
        return 2
    inc = lib.incidents.get(a.id)
    if inc is None:
        print(
            f"error: no incident `{a.id}`; have {', '.join(sorted(lib.incidents)) or 'none'}",
            file=sys.stderr,
        )
        return 2
    pl = plan(lib, inc, now)
    if pl is None:
        print(
            f"error: `{a.id}` cannot be planned: unknown playbook or missing times", file=sys.stderr
        )
        return 2
    print(render.plan_text(pl))
    bad = pl.overdue_steps() or pl.overdue_obligations() or pl.ack_overdue or pl.update_overdue
    return 1 if bad and a.fail_on_overdue and inc.status == "open" else 0


def _drill_results(lib: Library) -> list[tuple[str, str, list[str]]]:
    out = []
    for k in sorted(lib.drills):
        diffs = run_drill(lib, lib.drills[k])
        out.append((k, "pass" if not diffs else "FAIL", diffs))
    return out


def cmd_drill(a: argparse.Namespace) -> int:
    lib = _load(Path(a.root))
    if lib is None:
        return 2
    results = _drill_results(lib)
    for name, verdict, diffs in results:
        print(f"{verdict:5} {name}")
        for d in diffs:
            print(f"        {d}")
    failed = sum(1 for _, v, _ in results if v != "pass")
    print(f"{len(results)} drills: {failed} failed")
    return 1 if failed else 0


def _reports(lib: Library, now: datetime) -> dict[str, str]:
    return {
        "policy.md": render.policy_markdown(lib.policy),
        "playbooks.md": render.playbooks_markdown(lib),
        "coverage.md": render.coverage_markdown(lib),
        "incidents.md": render.incidents_markdown(lib, now),
        "drills.md": render.drills_markdown(_drill_results(lib)),
        "lint.md": render.findings_markdown(rules.run(lib, now)),
        "rules.md": render.rules_markdown(),
    }


def cmd_report(a: argparse.Namespace) -> int:
    root = Path(a.root)
    lib, now = _load(root), _now(a)
    if lib is None or now is None:
        return 2
    reports = _reports(lib, now)
    out = root / "reports"
    if a.check:
        stale = [
            n
            for n, text in reports.items()
            if not (out / n).is_file() or (out / n).read_text(encoding="utf-8") != text
        ]
        for n in stale:
            print(
                f"stale: reports/{n}; run `aip report --now {a.now}` and commit the result",
                file=sys.stderr,
            )
        return 1 if stale else 0
    out.mkdir(exist_ok=True)
    for n, text in reports.items():
        (out / n).write_text(text, encoding="utf-8")
    print(f"wrote {len(reports)} reports to {out}")
    return 0


def cmd_rules(a: argparse.Namespace) -> int:
    for r in rules.REGISTRY:
        print(f"{r.id}  {r.severity:7} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aip",
        description="AI incident playbooks: severity, step deadlines, notification clocks and drills. A planning aid, not legal advice.",
    )
    p.add_argument("--version", action="version", version=f"aip {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, fn: object, help_: str, *, now: bool = False) -> argparse.ArgumentParser:
        s = sub.add_parser(name, help=help_)
        s.add_argument("--root", default=".", help="repository root (default: .)")
        if now:
            s.add_argument(
                "--now",
                required=True,
                help="the time to judge by, with an offset, e.g. 2026-11-15T12:00:00Z",
            )
        s.set_defaults(fn=fn)
        return s

    s = add("lint", cmd_lint, "check the policy, playbooks and incident records", now=True)
    s.add_argument("--fail-on", choices=rules.LEVELS, default="high")
    s.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    s = add(
        "classify",
        cmd_classify,
        "which severity would these facts get, and which clocks would start",
    )
    s.add_argument("--data-exposed", choices=DATA_VALUES, default="none")
    s.add_argument("--harm", choices=HARM_VALUES, default="none")
    for name in BOOL_FACTS:
        s.add_argument("--" + name.replace("_", "-"), action="store_true")
    s.add_argument("--users-affected", type=int, default=0)
    s = add("plan", cmd_plan, "the state of one incident: steps, notifications, updates", now=True)
    s.add_argument("id")
    s.add_argument("--fail-on-overdue", action="store_true")
    add(
        "drill",
        cmd_drill,
        "replay the scripted drills and check the playbooks give the expected state",
    )
    s = add("report", cmd_report, "write or check the generated reports", now=True)
    s.add_argument("--check", action="store_true", help="fail if the reports on disk are stale")
    add("rules", cmd_rules, "list the lint rules")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.fn(args)
    return code
