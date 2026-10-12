"""All automated captures are synthetic and generated deterministically."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def generator():
    spec = importlib.util.spec_from_file_location(
        "fixtures_generator", ROOT / "fixtures/generate_fixtures.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def fixtures(generator):
    # Reproduction is explicit; do not silently regenerate oracles before assertions.
    assert (ROOT / "fixtures/ground_truth/expected.json").exists(), (
        "Run fixtures/generate_fixtures.py"
    )
    return ROOT / "fixtures"
