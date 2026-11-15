# ADR 0004: Playbooks are tested with lint and with scripted drills

## Status

Accepted

## Context

A playbook is written once and read for the first time in an emergency. Its faults are quiet: a step due before the step it depends on, a role nobody holds, a containment step slower than the policy allows, an obligation no step satisfies. A tabletop exercise finds some of these, once, with a room full of people. It does not run again when the playbook changes.

## Decision

Two kinds of check run in CI. Lint (`AIP001` to `AIP016`) checks the structure: valid phases and roles, no prerequisite cycles, a prerequisite not due later than the step that needs it, containment within the policy's limit at the top levels, a backup for every role, someone able to fill every role, a playbook for every kind of incident, and a step for every obligation. Drills are scripted incidents in `drills/` with an `[expect]` table: at a stated time the plan must show exactly these steps overdue and done. `aip drill` replays them and names every difference, and the tests check that each drill fails when its expectation is altered, so a drill cannot pass by being vague.

## Consequences

- Changing a deadline, a role or a prerequisite shows its effect on a worked incident before anyone depends on it.
- A drill is a rehearsal of the *plan's arithmetic*, not of the people. It does not tell you whether the on-call person will pick up the phone.
- Drills encode what their author expected. A wrong expectation passes quietly if the playbook has the same mistake; review the expectation as carefully as the playbook.
