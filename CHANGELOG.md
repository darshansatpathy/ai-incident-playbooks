# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-13

### Added
- Severity classification from facts, with the reasons shown; the declared level can only be raised.
- Playbooks as data with per-severity step deadlines, prerequisites, roles with backups and evidence requirements.
- Notification clocks as configurable obligations. The example deadlines are placeholders and lint says so.
- `aip plan`, `aip classify`, `aip drill` and generated reports; the clock is always passed in.
- Sixteen lint rules (AIP001 to AIP016), five example playbooks, three synthetic incidents, three drills, four ADRs and two runbooks.

[0.1.0]: https://github.com/darshansatpathy/ai-incident-playbooks/releases/tag/v0.1.0
