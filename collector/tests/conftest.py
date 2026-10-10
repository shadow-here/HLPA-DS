import os
import sys

import mongomock
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hlpa_collector import redact  # noqa: E402
from hlpa_collector.engine import RuleEngine, Tagger  # noqa: E402


@pytest.fixture(autouse=True)
def fixed_redaction_key():
    redact.set_key("test-redaction-key")
    yield


@pytest.fixture
def db():
    return mongomock.MongoClient().hlpa


def load_rules():
    import yaml
    path = os.path.join(os.path.dirname(__file__), "..", "rules", "rules.yml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def engine(db):
    cfg = load_rules()
    eng = RuleEngine(db)
    eng.load(cfg["rules"], indicators=set())
    eng.tagger = Tagger(cfg["taggers"])
    return eng


@pytest.fixture
def tagger():
    return Tagger(load_rules()["taggers"])
