# AI incident playbooks

[![CI](https://github.com/darshansatpathy/ai-incident-playbooks/actions/workflows/ci.yml/badge.svg)](https://github.com/darshansatpathy/ai-incident-playbooks/actions/workflows/ci.yml)
[![CodeQL](https://github.com/darshansatpathy/ai-incident-playbooks/actions/workflows/codeql.yml/badge.svg)](https://github.com/darshansatpathy/ai-incident-playbooks/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Typed](https://img.shields.io/badge/mypy-strict-informational)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-success)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**When an AI system leaks data, acts without authority or gives harmful answers, what is overdue right now, who has to do what next, and which notification clock is running?**

Most incident documents are PDFs that nobody can query at 3 a.m. This repository keeps AI incident playbooks as data. Severity is worked out from facts, with the reasons shown. Each step has a deadline that depends on severity. A notification clock starts when the organisation becomes aware, and completing the step that sends it stops the clock. The playbooks are tested before anyone needs them: a linter checks their structure, and scripted drills replay a made-up incident and check the plan shows exactly the state it should.

**This is a planning aid. It is not legal advice and does not say what any law requires.** Every notification deadline in the example is a placeholder, marked as such, to be replaced with figures your legal team gives you for your jurisdictions and contracts. The incidents, people and tickets are invented.

## The example

An agent placed purchase orders above its approval limit. It was declared sev1, and at the pinned time the plan reads:

```
$ aip plan inc-2026-002 --now 2026-11-15T12:00:00Z
inc-2026-002: run at sev1 (declared sev1, facts give sev1)
  because: An agent took actions of its own and money or people were harmed
  acknowledge by 2026-11-14T08:15:00+00:00: DONE
  next update by 2026-11-14T11:00:00+00:00 (OVERDUE)
  steps:
    done late  confirm-action  [detect, security-lead] due 2026-11-14T08:15:00+00:00
    done late  revoke-agent-access  [contain, engineering-lead] due 2026-11-14T08:15:00+00:00
    done       brief-executive  [notify, incident-commander] due 2026-11-14T10:00:00+00:00
    done late  reverse-actions  [recover, engineering-lead] due 2026-11-14T16:00:00+00:00
    overdue    assess-permissions  [assess, security-lead] due 2026-11-15T08:00:00+00:00
    blocked    restore-with-limits  [recover, engineering-lead] due 2026-11-17T08:00:00+00:00
    blocked    post-incident-review  [review, incident-commander] due 2026-11-28T08:00:00+00:00
  notifications:
    done       ob-executive-brief (Executive sponsor) due 2026-11-14T12:00:00+00:00
```

Containment finished 35 minutes late against a 15-minute sev1 deadline, an update is overdue, and the next step is waiting on one that is not done. One of the drills declares the same kind of incident as sev3 and shows that the plan is still run at sev1, so credentials not yet revoked at thirty minutes are already overdue.

## What it enforces

| Question | How |
|---|---|
| Why is this sev1? | Severity rules are data. The most severe matching level wins and the reasons of the rules that set it are shown. `aip classify` answers "what if" without a record. |
| Can someone under-call an incident to buy time? | The incident is run at the more severe of what was declared and what the facts give. Lint reports an understated declaration as high. |
| What is overdue? | Computed from the record and the time you pass in. Nothing reads the clock, so the same record and time always give the same plan. |
| Who may do each step? | A person holding the step's role, or a role behind it in the backup chain. Lint reports anyone else, and a step done before its prerequisite. |
| Is any role a single point of failure? | Every role needs a backup, backups may not loop, and every role a playbook needs must be fillable by someone. |
| Is containment fast enough? | The policy caps how soon the first containment step is due at the top levels; lint fails a playbook that exceeds it. |
| Which notification clocks are running, and is each one satisfied? | An obligation names its audience, the facts that trigger it, when its clock starts and how long it runs. Completing the step that notifies it stops it. An obligation no step satisfies is a lint failure. |
| Can a legal deadline be a guess? | A legal obligation carries a source, a reviewer and a review date, or is marked as a placeholder, which lint reports on every run. |
| Can an incident be closed with work outstanding? | No. Lint fails a closed incident with steps not done or notifications not sent. |
| Do the playbooks work? | Drills replay scripted incidents at a stated time and compare the plan to what was expected. CI runs them. |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

aip classify --data-exposed personal --customer-facing --ongoing    # severity, reasons, clocks that would start
aip plan inc-2026-002 --now 2026-11-15T12:00:00Z                     # the state of one incident
aip lint --now 2026-11-15T12:00:00Z                                  # policy, playbooks and incident records
aip drill                                                            # replay the scripted drills
aip report --now 2026-11-15T12:00:00Z                                # write the reports (add --check to fail if stale)
make check                                                           # ruff, mypy --strict, pytest with an 85% coverage gate
```

The time is always an argument and must carry an offset, so a plan can be replayed at any moment of an incident and CI can pin it. To run an incident see [declaring and running an incident](docs/runbooks/declaring-and-running-an-incident.md); to change a playbook or a deadline see [changing a playbook or a notification deadline](docs/runbooks/changing-a-playbook-or-a-notification-deadline.md) and [file formats](docs/formats.md).

## What is in it

| Path | What |
|---|---|
| `src/playbooks/` | `model.py` (loaders), `engine.py` (classification, planning, drills), `rules.py`, `render.py`, `cli.py` |
| `policy/` | Severity levels and rules, roles with backups, people, notification obligations (example, with placeholder deadlines) |
| `playbooks/` | Five playbooks: data exposure, harmful output, unauthorised action, model regression, vendor outage |
| `incidents/` | Three invented incidents: one closed, one open and late, one on schedule |
| `drills/` | Three scripted rehearsals with expected outcomes |
| `reports/` | Policy, playbooks, coverage, incidents, drills, lint and rules (generated) |
| `docs/` | [Formats](docs/formats.md), ADRs, runbooks |

## Lint rules

| Rule | Severity | Checks |
|---|---|---|
| `AIP001` | high | The policy's levels, phases, kinds and rules are consistent |
| `AIP002` | high | Playbooks are well formed: phases, evidence kinds, deadlines, unique step ids |
| `AIP003` | high | Step roles exist, prerequisites exist and are acyclic, and are not due later than the step |
| `AIP004` | high | Every playbook has the required phases at the most severe level |
| `AIP005` | high | Containment is due within the policy's limit |
| `AIP006` | high | Every role has a backup and backups do not loop |
| `AIP007` | high | Every role a playbook needs can be filled by someone |
| `AIP008` | high | Every kind of incident has a playbook |
| `AIP009` | high | Obligations are well formed |
| `AIP010` | high | Legal deadlines are reviewed, or marked as placeholders (low) |
| `AIP011` | high | Every obligation has a step that satisfies it, and every step refers to a real obligation |
| `AIP012` | high | Incident records have valid references, times, people and evidence |
| `AIP013` | high | Steps are done by the right person and after their prerequisites |
| `AIP014` | high | Severity is not understated |
| `AIP015` | high | Nothing open is overdue (notifications high, steps and updates medium) |
| `AIP016` | high | A closed incident has every step and notification done |

## Design decisions

- [ADR 0001](docs/adr/0001-a-plan-is-computed-from-the-record-and-the-clock-is-passed-in.md): a plan is computed from the record, and the clock is passed in.
- [ADR 0002](docs/adr/0002-severity-comes-from-facts-and-the-declared-level-can-only-be-raised.md): severity comes from facts with reasons, and the declared level can only be raised.
- [ADR 0003](docs/adr/0003-notification-deadlines-are-data-you-set-with-counsel.md): notification deadlines are data you set with your legal team, and the repository asserts none.
- [ADR 0004](docs/adr/0004-playbooks-are-tested-with-drills-and-lint.md): playbooks are tested with lint and with scripted drills.

Runbooks: [declaring and running an incident](docs/runbooks/declaring-and-running-an-incident.md), [changing a playbook or a notification deadline](docs/runbooks/changing-a-playbook-or-a-notification-deadline.md).

## Where it fits

An incident's `kind` and its facts line up with the controls in the [AI use case register](https://github.com/darshansatpathy/ai-use-case-register) and the threats in the [AI threat model as code](https://github.com/darshansatpathy/ai-threat-model-as-code), and a failing attack in the [LLM red-team harness](https://github.com/darshansatpathy/llm-red-team-harness) is the kind of finding that starts one. Nothing here reads or checks those repositories.

## What has and has not been verified

Verified, by running it:

- The suite of 109 tests, including the severity rules on both sides of each condition (a minimum is inclusive), the highest-level rule, every step state, deadline boundaries (a step due exactly now is not overdue and one second later is; a notification sent exactly at its deadline is not late), the notification clocks from awareness and from declaration, every lint rule with a failing case and a case that must stay clean, the drills, and the CLI.
- Line coverage of about 98% of the package, measured with a tracer in the build environment, and enforced at 85% in CI.
- Mutation checks: 42 deliberate bugs in the engine, the lint rules, the loaders and the CLI, each caught by at least one test. The checks found three gaps (a notification sent exactly at its deadline, a zero-minute level, and a closed incident failing the overdue check), and tests were added for each.
- Lint found two timing mistakes in the author's own playbook data while it was being written (a step due before the step it depends on), which is the kind of mistake it is for.
- Drills are checked to fail when their expectation is altered, so none passes by being vague. CI runs lint, the drills and the report check on the example.

Not verified, or not claimed:

- **This is not legal advice, and no deadline here is a statement of what a law requires.** The notification obligations are placeholders with generic audiences ("Regulator A"). Which duties apply to you, to whom, from when and within how long is for your lawyers to say. Lint reports each placeholder on every run.
- **The facts in a record are taken as given.** An incident recorded with the wrong facts gets the wrong severity. People can raise the level; nothing lowers it for them.
- **The severity rules are coarse.** A handful of facts cannot capture what makes an incident serious. They order the response; they do not replace judgement.
- **Events are text.** The tool cannot check that a step was done, that the person did it, or that the evidence is real. It checks that the person holds the role.
- **A drill rehearses the arithmetic of the plan, not the people.** It does not tell you whether someone will answer the phone.
- **No workflow.** There are no notifications, pagers or reminders. The tool says what is overdue when someone runs it.
- **One file per incident suits a few at a time.** A real programme would put this logic behind the incident tooling it already uses.
- **The example is invented.** The roles, deadlines, severities and playbook steps are examples to argue with, not recommendations.
- Written and tested by an AI assistant (Claude) working with the repository owner; the design has not had an independent review.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
