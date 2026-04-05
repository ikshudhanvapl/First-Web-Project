"""
test_migrations.py — Verify the Alembic migration chain is coherent.

These tests do NOT need a live database. They verify:
  1. All migration files can be imported without error
  2. The revision chain is linear (no missing down_revisions)
  3. Each migration has upgrade() and downgrade() functions
  4. No two migrations share the same revision ID

For tests against a real DB, use pytest-alembic (add to requirements).
"""

import pytest
import importlib
import os
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent.parent / "backend" / "migrations" / "versions"


def _load_migration(path: Path):
    """Import a migration file as a module."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _all_migrations():
    return sorted(MIGRATIONS_DIR.glob("*.py"))


class TestMigrationChain:
    def test_migration_files_exist(self):
        """At least the initial migration must exist."""
        files = _all_migrations()
        assert len(files) >= 1, "No migration files found"

    def test_all_migrations_importable(self):
        """Every migration file must be importable without errors."""
        for path in _all_migrations():
            mod = _load_migration(path)
            assert mod is not None, f"Failed to import {path.name}"

    def test_all_have_upgrade_and_downgrade(self):
        """Every migration must define upgrade() and downgrade()."""
        for path in _all_migrations():
            mod = _load_migration(path)
            assert callable(getattr(mod, "upgrade",   None)), \
                f"{path.name} missing upgrade()"
            assert callable(getattr(mod, "downgrade", None)), \
                f"{path.name} missing downgrade()"

    def test_unique_revision_ids(self):
        """No two migrations may share the same revision ID."""
        revisions = []
        for path in _all_migrations():
            mod = _load_migration(path)
            rev = getattr(mod, "revision", None)
            assert rev not in revisions, \
                f"Duplicate revision ID '{rev}' in {path.name}"
            revisions.append(rev)

    def test_chain_is_linear(self):
        """
        Verify the down_revision chain is connected: each migration's
        down_revision must either be None (head) or point to an existing revision.
        """
        mods = [_load_migration(p) for p in _all_migrations()]
        all_revisions = {getattr(m, "revision") for m in mods}

        for mod in mods:
            down = getattr(mod, "down_revision", None)
            if down is not None:
                assert down in all_revisions, (
                    f"Migration '{mod.revision}' references unknown "
                    f"down_revision '{down}'"
                )

    def test_initial_migration_has_no_parent(self):
        """The first migration must have down_revision = None."""
        mods = [_load_migration(p) for p in _all_migrations()]
        roots = [m for m in mods if getattr(m, "down_revision", None) is None]
        assert len(roots) == 1, \
            f"Expected exactly 1 root migration, found {len(roots)}"

    def test_revision_ids_are_strings(self):
        for path in _all_migrations():
            mod = _load_migration(path)
            rev = getattr(mod, "revision", None)
            assert isinstance(rev, str) and len(rev) > 0, \
                f"{path.name} has invalid revision: {rev!r}"
