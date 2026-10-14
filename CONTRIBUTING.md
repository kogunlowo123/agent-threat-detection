# Contributing

## Setup

```bash
uv sync --all-extras
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, tests with at
  least 90% branch coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`.
- Public API changes are recorded in `CHANGELOG.md`.
- Architecturally significant decisions get an ADR in
  `docs/architecture/adr/`.
- No credentials, customer data or PHI in code, tests or fixtures. Use
  synthetic data only.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/agent_threat_detection/security`, `src/agent_threat_detection/detection`, `rules/`, `policies/` or `deployments/` need approval
from a member of the security code owners group (see `CODEOWNERS`).

## Detection changes

A change to a detector, its defaults or a rule must keep
`tests/unit/test_detection_quality.py` green and must update the measured
numbers in `docs/architecture/detection-evaluation.md`
(`make evaluate` prints them). New Sigma-style rules go in `rules/` with
ATT&CK or ATLAS tags, a `falsepositives` entry and a unit test that shows the
rule firing and not firing.
