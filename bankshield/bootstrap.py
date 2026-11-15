"""Reset and seed: estate (with replayed history), baseline logs, attack scenarios, policies,
first scan, first audit checkpoint. Shared by scripts/seed.py and `python -m bankshield seed`."""

from __future__ import annotations

from typing import Callable

from . import db
from .detection import run_log_detections, scan_assets
from .rag import ingest_policies
from .rag.retriever import invalidate
from .simulator import SCENARIOS, generate_baseline_logs, run_attack_scenario, seed_assets, seed_history


def seed(attacks: bool = True, history_days: int = 10, log: Callable[[str], None] = print) -> dict:
    db.reset()
    invalidate()
    with db.session() as c:
        if history_days:
            log(f"history     : {seed_history(c, history_days)} daily scans replayed")
        log(f"assets      : {seed_assets(c)}")
        log(f"baseline log: {generate_baseline_logs(c)} rows")
        if attacks:
            for s in SCENARIOS:
                log(f"attack      : {s} ({run_attack_scenario(c, s)} rows)")
        log(f"policy      : {ingest_policies(c)} clauses")
        posture = scan_assets(c)
        log(f"posture scan: {posture}")
        det = run_log_detections(c)
        log(f"detections  : {det}")
        db.audit(c, "system:seed", "seed", {"attacks": attacks, "history_days": history_days})
        cp = db.audit_checkpoint(c, "system:seed")
        log(f"audit       : checkpoint at seq {cp['seq']}")
    log(f"db          : {db.config.DB_PATH}")
    return {"posture": posture, "detections": det}
