# File formats

All TOML. Times are written with an offset (`2026-11-15T09:30:00Z` or `+05:30`); a time without one is an error, because "10:00" means different things to people in different places.

## `policy/policy.toml`

| Key | Meaning |
|---|---|
| `phases` | The ordered phases a step can belong to (the example: detect, contain, assess, notify, recover, review). |
| `required_phases` | Phases every playbook must have a step in, at the most severe level. |
| `kinds` | The kinds of incident, such as `data_exposure`. Every kind needs a playbook. |
| `[contain_within_minutes]` | Per level, how soon the first containment step must be due after declaration. |
| `[[levels]]` | Most severe first. `name`, `ack_minutes` (acknowledge within) and `update_minutes` (update at least this often). |
| `[[severity_rules]]` | `level`, `because` and `when`. The most severe level any rule gives wins; with no match the least severe applies. |
| `[roles.<name>]` | `backup` (another role) or `final = true` for the top of the chain. |
| `[people.<id>]` | `roles = [...]`. Use ids, not real names, in a public repository. |
| `[[obligations]]` | Notification clocks. See below. |

A `when` table lists conditions on facts, all of which must hold: `fact = value`, `fact_in = [values]` for the two enumerated facts, `fact_min = n` for a number (inclusive). The facts are:

| Fact | Values |
|---|---|
| `data_exposed` | `none`, `internal`, `personal`, `confidential` |
| `harm` | `none`, `reputational`, `financial`, `physical` |
| `customer_facing`, `autonomous_action`, `ongoing`, `regulated_domain` | true or false |
| `users_affected` | a whole number |

### Obligations

`id`, `kind` (`legal` or `internal`), `audience`, `when`, `clock_from` (`aware`: when the organisation became aware; or `declared`), `deadline_hours`, and for legal ones `example`, `source`, `reviewed_by`, `reviewed_on`. **A legal obligation either carries a source, a reviewer and a review date, or is marked `example = true`, which lint reports as a placeholder.** The example file has only placeholders. This repository states no legal deadline.

## `playbooks/<id>.toml`

`id` (equal to the file name), `title`, `applies_to` (incident kinds) and `[[steps]]`:

| Field | Meaning |
|---|---|
| `id`, `phase`, `role`, `action` | What, in which phase, by which role. |
| `due` | Minutes after declaration, by level: `{ sev1 = 15, sev2 = 60 }`. **A step with no entry for a level does not apply at that level.** |
| `requires` | Step ids that must be done first. A prerequisite that does not apply at the incident's level is not waited for. |
| `evidence` | `none`, `ticket`, `log`, `link` or `text`: what the person completing it must record. |
| `notifies` | An obligation id. Completing this step satisfies that clock. The step applies only if the obligation applies to the incident's facts. |

## `incidents/<id>.toml`

`id` (equal to the file name), `title`, `kind`, `playbook`, `declared_at`, `aware_at` (never later than `declared_at`), `declared_severity`, `status` (`open` or `closed`), a `[facts]` table and `[[events]]`:

- `kind = "ack"`: someone took charge. Needs `at`, `by`.
- `kind = "update"`: a status update went out. Needs `at`, `by`, and may have a `note`.
- a step event (the default kind): `at`, `step`, `by` and `evidence`.

`by` is a person id from the policy. The incident is run at the more severe of `declared_severity` and what the facts give, so an understated declaration cannot slow the response down.

## `drills/<id>.toml`

The same fields as an incident, plus `at` (the time to judge by), an optional `note`, and an `[expect]` table: `severity`, `overdue_steps`, `overdue_obligations`, `done_steps` (lists, compared as sets), `update_overdue` and `ack_overdue`. `aip drill` replays each drill and names every difference.
