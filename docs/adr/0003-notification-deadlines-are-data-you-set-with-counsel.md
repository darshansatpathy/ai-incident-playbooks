# ADR 0003: Notification deadlines are data you set with your legal team, and the repository asserts none

## Status

Accepted

## Context

Many AI incidents carry a duty to tell someone (a regulator, customers, a partner) within a stated time, and missing it is often worse than the incident. The deadlines depend on jurisdiction, sector, contract and the facts, and they change. A public repository that states them risks being copied as if it were advice, and being wrong. A playbook that ignores them leaves the most time-sensitive step to memory.

## Decision

A notification is an *obligation* in the policy: an audience, the facts that trigger it, a clock that starts at awareness or at declaration, and a length in hours. A playbook step names the obligation it satisfies. Completing that step stops the clock, and an unsatisfied clock past its deadline is a high-severity finding. The deadlines in the example are placeholders, marked `example = true`, with obviously generic audiences ("Regulator A"), and lint reports each as a placeholder. A legal obligation that is not a placeholder must carry a source, a reviewer and a review date, or lint fails it. Every command that shows a clock says it is not legal advice.

## Consequences

- The tool makes the clock visible and the step unmissable without claiming to know the number.
- Adopting this means someone with authority sets and reviews the figures once, and the review date makes staleness visible.
- A reviewer's name and date are text. The tool cannot check that the review happened or that the figure is right.
- The clock starts from the time the organisation became aware. Deciding when that was is a human judgement the record has to state, and the tool does not decide it.
