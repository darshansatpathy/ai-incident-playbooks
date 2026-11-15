# Declaring and running an incident

## Purpose

Something has happened with an AI system and someone needs to take charge and keep the response on time.

## Triggers

- A report or alert that an AI system exposed data, produced harmful output, acted without authority, regressed or went down with its vendor.

## First checks

- Which kind is it? If it is two, pick the more serious and note the other in the title.
- Write down the time the organisation first knew. It starts the notification clocks and is not the same as the time you declare.
- Run `aip classify` with what you know. If you are unsure of a fact, use the more serious value and correct it later: the record can be changed, a missed clock cannot.

## Steps

1. Create `incidents/inc-YYYY-NNN.toml` from a similar one: `id` equal to the file name, `kind`, `playbook`, `declared_at`, `aware_at`, `declared_severity` and the `[facts]`. If you are unsure, declare higher. You cannot make the plan slower by declaring lower, but a lower declaration hides the incident from people.
2. `aip plan inc-YYYY-NNN --now NOW`. Read the severity and the reasons, the first steps, and any notification clock that has started.
3. Record an `ack` event when someone takes charge.
4. As each step is done, add an event with the time, who did it and the evidence the step asks for. Add an `update` event each time you tell people the state.
5. Re-run `aip plan ... --now NOW` and `aip lint --now NOW`. Overdue work is shown, and so is a step done by someone who does not hold its role.
6. When the facts change, change them in the record. The severity and every deadline follow.
7. Close the incident (`status = "closed"`) only when every step and every notification applying to it is done. Lint will not accept it otherwise.

## Verification

- `aip plan` shows nothing overdue, an acknowledgement and an update within their cadence.
- `aip lint --now NOW` has no findings for the incident.

## Escalation

- A step past its deadline goes to the role's backup (`aip plan` names the role; the policy names the backup).
- A notification clock that is about to run out goes to the legal contact at once, whatever else is happening.
