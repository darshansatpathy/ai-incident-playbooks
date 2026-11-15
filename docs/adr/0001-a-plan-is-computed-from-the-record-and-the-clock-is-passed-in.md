# ADR 0001: A plan is computed from the record, and the clock is passed in

## Status

Accepted

## Context

During an incident the question is "what is overdue and what is next". A tracker that stores a status per step goes stale the moment someone forgets to update it, and a tool that reads the system clock cannot be tested, replayed or reproduced in a review afterwards.

## Decision

An incident record holds only facts and events: when it was declared and when the organisation became aware, the facts, and what was done, by whom, and when. Everything else is computed. Each step's deadline is the declaration time plus the minutes the playbook gives for the incident's severity. A step is done, overdue (past due and not done), blocked (waiting for a prerequisite and not yet due) or open. The time to judge by is an argument (`--now`) and must carry an offset. Nothing in the code reads the clock.

## Consequences

- The same record and the same `--now` always give the same plan, so a review can replay an incident at any moment during it, and CI can pin the time.
- A step that was finished late is shown as done late, not as overdue: lateness is history, overdue is a present need.
- The record is only as good as the people who enter events. The tool cannot know a step was done unless someone records it, and it cannot check that the evidence is true.
- Deadlines are relative to declaration. If declaration itself is late, the plan is generous; the awareness time is kept separately for the notification clocks for that reason.
