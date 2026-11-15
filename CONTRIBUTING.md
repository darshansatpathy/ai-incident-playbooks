# Contributing

Thanks for taking the time to improve this project.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make check      # ruff, mypy --strict, pytest with an 85% coverage gate
make example    # the checks CI runs on the example playbooks
```

## What a change needs

- Change `playbooks/`, `policy/`, `incidents/` and `drills/`, never `reports/`. Run `aip report --now TIME` and commit the result; CI fails if they differ. CI pins the time, so the reports do not change as time passes.
- The example notification deadlines are placeholders. Do not replace one with a figure unless it carries a source, a reviewer and a review date, and do not present any of them as what a law requires.
- A change to a deadline, a role or a prerequisite needs a drill that fails if the change is reverted.
- A new lint rule has an ID, a severity, a reason, a failing-case test and a case that must stay clean. Deadline rules need a test on both sides of the boundary.
- Keep the examples synthetic: no real incidents, people, systems or reference numbers.
- Decisions about what a severity means or how a clock starts get an ADR in `docs/adr/`. Update `CHANGELOG.md` for anything a user would notice.

## Pull requests

Keep them focused, describe the behaviour change and how you tested it, and make sure
CI is green. Security issues go through private reporting, see [SECURITY.md](SECURITY.md).
