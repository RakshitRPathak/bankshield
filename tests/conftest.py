import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolated DB per test session.
_tmp = tempfile.mkdtemp(prefix="bankshield-test-")
os.environ["BANKSHIELD_DATA_DIR"] = _tmp
os.environ["BANKSHIELD_DB"] = str(Path(_tmp) / "test.db")
os.environ.pop("BANKSHIELD_AUTH", None)
os.environ.pop("BANKSHIELD_AUDIT_KEY", None)

from bankshield import config, db  # noqa: E402
from bankshield.detection import run_log_detections, scan_assets  # noqa: E402
from bankshield.rag import ingest_policies  # noqa: E402
from bankshield.rag.retriever import invalidate  # noqa: E402
from bankshield.simulator import SCENARIOS, generate_baseline_logs, run_attack_scenario, seed_assets  # noqa: E402


@pytest.fixture()
def conn():
    db.reset()
    invalidate()
    c = db.connect()
    seed_assets(c)
    generate_baseline_logs(c, hours=6, per_hour=10)
    for s in SCENARIOS:
        run_attack_scenario(c, s)
    ingest_policies(c)
    scan_assets(c)
    run_log_detections(c)
    yield c
    c.close()
    invalidate()


@pytest.fixture()
def client(conn):
    from fastapi.testclient import TestClient
    from bankshield.api import main
    main._hits.clear()
    return TestClient(main.app)


@pytest.fixture()
def as_user():
    return lambda u: {"X-User": u}


@pytest.fixture()
def restore_config():
    """Tests that flip config switches get them put back."""
    saved = {k: getattr(config, k) for k in ("AUTH_MODE", "SECRET_KEY", "AUDIT_HMAC_KEY", "RATE_LIMIT_PER_MIN", "FOUR_EYES", "LLM_BACKEND")}
    yield config
    for k, v in saved.items():
        setattr(config, k, v)
