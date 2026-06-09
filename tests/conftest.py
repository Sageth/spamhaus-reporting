"""Shared test setup.

The main script is named ``spam-automation.py`` — a hyphen makes it impossible
to import with a normal ``import`` statement, so we load it by path once and
expose it as the ``spam`` fixture (and a module-level ``spam`` for direct import
in test modules via ``from conftest import spam``).
"""
import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MODULE_PATH = _ROOT / 'spam-automation.py'
FIXTURES = pathlib.Path(__file__).resolve().parent / 'fixtures'


def _load_module():
    spec = importlib.util.spec_from_file_location('spam_automation', _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


spam = _load_module()


@pytest.fixture
def eml():
    """Return a loader that reads a fixture .eml file as raw bytes."""
    def _load(name):
        return (FIXTURES / name).read_bytes()
    return _load
