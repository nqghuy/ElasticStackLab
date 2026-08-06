from __future__ import annotations
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config import Settings
from pipeline.models import AtomicTest

logger = logging.getLogger(__name__)

SCRIPT_PATH = 'scripts/run_atomic.ps1'
ROUND_FILE = 'output/current_round.json'
STDOUT_LOG = 'logs/atomic_stdout.log'

TIMEOUT = 120

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def _write_round_file(tests: list[AtomicTest]) -> None:
    payload = [{'Technique': t.technique, 'Test': t.test_number} for t in tests]
    with open(ROUND_FILE, 'w') as f:
        json.dump(payload, f, indent=4)

def _append_log(text:str) -> None:
    with open(STDOUT_LOG, 'a') as f:
        f.write(text)
        f.write('\n')

# return (start, end) to query elastic later
def run_atomic_tests(settings: Settings, tests: list[AtomicTest]) -> tuple[str, str]:
    _write_round_file(tests)

    cmd = [
        "pwsh",
        "-File", SCRIPT_PATH,
        "-JsonFile", ROUND_FILE
    ]

    start = _now_iso()
    logger.info("START TIME: %s", start)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired as e:
        _append_log(f"[TIMEOUT] {start} {e}")
        raise

    _append_log(result.stdout)
    _append_log(result.stderr)

    if result.returncode != 0:
        logger.error("run_atomic.ps1 exited with code %d", result.returncode)
        raise RuntimeError(
            f"run_atomic.ps1 failed (exit code {result.returncode}). "
            f"See {STDOUT_LOG} for details."
        )

    end = _now_iso()
    logger.info('END TIME: %s', end)
    return start, end

