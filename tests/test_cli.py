from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from playbooks.cli import REPORTS, build_parser, main
from tests.helpers import ROOT

NOW = ["--now", "2026-11-15T12:00:00Z"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for d in ("playbooks", "policy", "incidents", "drills"):
        shutil.copytree(ROOT / d, tmp_path / d)
    return tmp_path


def run(repo: Path, *args: str) -> int:
    return main([args[0], "--root", str(repo), *args[1:]])


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and "aip 0.1.0" in capsys.readouterr().out
    assert "classify" in build_parser().format_help()


def test_lint_passes_the_example_at_high_and_fails_at_medium(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "lint", *NOW) == 0
    out = capsys.readouterr().out
    assert "AIP015 inc-2026-002" in out and "5 playbooks, 3 incidents, 16 rules" in out
    assert run(repo, "lint", *NOW, "--fail-on", "medium") == 1


def test_lint_formats(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run(repo, "lint", *NOW, "--format", "json")
    assert json.loads(capsys.readouterr().out)[0]["rule"].startswith("AIP")
    run(repo, "lint", *NOW, "--format", "markdown")
    assert capsys.readouterr().out.startswith("# Lint")


def test_a_bad_time_is_an_error_not_a_crash(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for bad in ("tomorrow", "2026-11-15", "2026-11-15T12:00:00"):
        assert run(repo, "lint", "--now", bad) == 2
    assert "with an offset" in capsys.readouterr().err
    assert run(repo, "lint", "--now", "2026-11-15T12:00:00+05:30") == 0


def test_commands_refuse_a_broken_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for args in (["lint", *NOW], ["classify"], ["plan", "x", *NOW], ["drill"], ["report", *NOW]):
        assert main([args[0], "--root", str(tmp_path), *args[1:]]) == 2
    assert "error:" in capsys.readouterr().err


def test_lint_fails_on_a_bad_record(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = repo / "incidents" / "inc-2026-003.toml"
    f.write_text(
        f.read_text().replace('declared_severity = "sev3"', 'declared_severity = "sev9"'),
        encoding="utf-8",
    )
    assert run(repo, "lint", *NOW) == 1
    assert "AIP012" in capsys.readouterr().out


def test_classify_explains_the_severity_and_the_clocks(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "classify",
                "--root",
                str(ROOT),
                "--data-exposed",
                "personal",
                "--customer-facing",
                "--ongoing",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "severity: sev1" in out and "still happening" in out
    assert "ob-regulator-a" in out and "(placeholder)" in out and "not legal advice" in out
    assert main(["classify", "--root", str(ROOT)]) == 0
    out = capsys.readouterr().out
    assert "severity: sev4" in out and "no severity rule matched" in out and "  none" in out


def test_classify_flags(capsys: pytest.CaptureFixture[str]) -> None:
    main(["classify", "--root", str(ROOT), "--harm", "physical"])
    assert "severity: sev1" in capsys.readouterr().out
    main(["classify", "--root", str(ROOT), "--users-affected", "1000"])
    assert "severity: sev2" in capsys.readouterr().out
    main(["classify", "--root", str(ROOT), "--users-affected", "999"])
    assert "severity: sev4" in capsys.readouterr().out
    main(
        [
            "classify",
            "--root",
            str(ROOT),
            "--autonomous-action",
            "--regulated-domain",
            "--harm",
            "financial",
        ]
    )
    out = capsys.readouterr().out
    assert "severity: sev1" in out and "ob-executive-brief" in out and "ob-sector-regulator" in out


def test_plan_prints_the_state_and_can_fail_on_overdue(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "plan", "inc-2026-002", *NOW) == 0
    out = capsys.readouterr().out
    assert "run at sev1 (declared sev1, facts give sev1)" in out
    assert "OVERDUE" in out and "assess-permissions" in out and "done late" in out
    assert run(repo, "plan", "inc-2026-002", *NOW, "--fail-on-overdue") == 1
    assert run(repo, "plan", "inc-2026-003", *NOW, "--fail-on-overdue") == 0
    assert (
        run(repo, "plan", "inc-2026-001", "--now", "2027-01-01T00:00:00Z", "--fail-on-overdue") == 0
    )


def test_a_closed_incident_never_fails_the_overdue_check(repo: Path) -> None:
    f = repo / "incidents" / "inc-2026-003.toml"
    f.write_text(f.read_text().replace('status = "open"', 'status = "closed"'), encoding="utf-8")
    assert (
        run(repo, "plan", "inc-2026-003", "--now", "2027-01-01T00:00:00Z", "--fail-on-overdue") == 0
    )
    f.write_text(f.read_text().replace('status = "closed"', 'status = "open"'), encoding="utf-8")
    assert (
        run(repo, "plan", "inc-2026-003", "--now", "2027-01-01T00:00:00Z", "--fail-on-overdue") == 1
    )


def test_plan_reports_unknown_incidents_and_unplannable_ones(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "plan", "inc-nope", *NOW) == 2
    assert "no incident `inc-nope`; have inc-2026-001" in capsys.readouterr().err
    f = repo / "incidents" / "inc-2026-003.toml"
    f.write_text(
        f.read_text().replace('playbook = "pb-model-regression"', 'playbook = "zzz"'),
        encoding="utf-8",
    )
    assert run(repo, "plan", "inc-2026-003", *NOW) == 2
    assert "cannot be planned" in capsys.readouterr().err


def test_plan_shows_no_notifications_when_none_apply(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(repo, "plan", "inc-2026-003", *NOW)
    assert "none apply" in capsys.readouterr().out


def test_drill_passes_and_fails(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "drill") == 0
    assert "3 drills: 0 failed" in capsys.readouterr().out
    f = repo / "drills" / "drill-003-clean-run.toml"
    f.write_text(
        f.read_text().replace('[expect]\nseverity = "sev3"', '[expect]\nseverity = "sev1"'),
        encoding="utf-8",
    )
    assert run(repo, "drill") == 1
    out = capsys.readouterr().out
    assert "FAIL  drill-003" in out and "severity sev3, expected sev1" in out and "1 failed" in out


def test_report_writes_every_file_and_check_notices_staleness(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "report", *NOW, "--check") == 1
    assert "stale: reports/policy.md" in capsys.readouterr().err
    assert run(repo, "report", *NOW) == 0
    assert sorted(p.name for p in (repo / "reports").iterdir()) == sorted(REPORTS)
    assert run(repo, "report", *NOW, "--check") == 0
    (repo / "reports" / "incidents.md").write_text("old", encoding="utf-8")
    assert run(repo, "report", *NOW, "--check") == 1
    assert "stale: reports/incidents.md" in capsys.readouterr().err


def test_reports_depend_on_the_time(repo: Path) -> None:
    run(repo, "report", *NOW)
    assert run(repo, "report", "--now", "2026-12-15T12:00:00Z", "--check") == 1


def test_rules_lists_every_rule(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("AIP0") == 16 and "AIP001" in out and "AIP016" in out
