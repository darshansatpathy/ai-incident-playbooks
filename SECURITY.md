# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/darshansatpathy/ai-incident-playbooks/security/advisories/new)
for this repository. You should get an acknowledgement within three working days.

## Scope

In scope: the `aip` tool and library, in particular anything that lets an overdue step or notification be shown as on time, a lower declared severity slow a plan down, or a closed incident hide unfinished work. Out of scope: the example policy, playbooks and incidents, and whether any deadline or procedure meets a legal or regulatory requirement.

## Operating it safely

- The repository contains no secrets and no real incidents. The people (`person-a` and so on), tickets and links in the example are invented.
- `aip` makes no network calls. It writes only to `reports/`.
- A real incident record describes a weakness in a live system and may name people and customers. Keep a real repository private, and do not publish incident details before they are safe to publish.
- Events are names, times and text in a file. The tool cannot check that the person recorded as doing a step did it or that the evidence is true.
