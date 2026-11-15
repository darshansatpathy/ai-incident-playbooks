# Changing a playbook or a notification deadline

## Purpose

An incident, a drill or a review showed that a playbook is wrong, or a legal team has set a deadline.

## Triggers

- A post-incident review action.
- A drill that failed or a lint finding.
- Your legal team giving you a figure for an obligation.

## First checks

- Which playbooks and which obligations does the change touch? `reports/coverage.md` lists which playbook satisfies which obligation.
- For a deadline: who set it, from what source, and on what date? You will need all three.

## Steps

1. Edit the playbook in `playbooks/` or the policy in `policy/`. Change deadlines by level; a step with no entry for a level does not apply at that level.
2. For a legal deadline: set `deadline_hours`, fill in `source`, `reviewed_by` and `reviewed_on`, and remove `example = true`. Do not set a figure nobody has reviewed.
3. `aip lint --now NOW`. Fix anything at `high`. Common ones: a step due before its prerequisite, containment slower than the policy allows, an obligation no step notifies.
4. `aip drill`. If a drill now differs, decide whether the playbook or the drill's expectation is wrong. Do not edit an expectation just to make it pass.
5. Add or adjust a drill that would have caught the problem you are fixing.
6. `aip report --now NOW` and commit the playbook, drills and reports together. Record the decision in an ADR if it changes what a level, a role or an obligation means.

## Verification

- Lint has no `high` findings and every drill passes.
- A drill exists that fails if the change is reverted.

## Escalation

- A change that lengthens a containment deadline at the top two levels needs the incident commander's role holder to agree, in the pull request.
- A change to a legal deadline needs the legal contact named in the policy to review it.
