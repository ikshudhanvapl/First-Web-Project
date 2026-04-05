## What does this PR do?

<!-- One paragraph summary -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Dependency update
- [ ] Database migration

## Checklist

- [ ] `pytest tests/` passes locally
- [ ] `ruff check backend/ tests/` passes
- [ ] New code has tests (coverage maintained ≥ 70%)
- [ ] If schema changed: Alembic migration included and tested (upgrade + downgrade)
- [ ] If OPA policy changed: `opa test policies/` passes
- [ ] No secrets, keys, or credentials in this PR
- [ ] README / docs updated if needed

## Database migrations

- [ ] No schema changes in this PR
- [ ] Schema changed — migration file included: `migrations/versions/XXXX_*.py`

## Breaking changes

<!-- If yes, describe the impact and migration path -->
None

## Screenshots / logs

<!-- If applicable -->
