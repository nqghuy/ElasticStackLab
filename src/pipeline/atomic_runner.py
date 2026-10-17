from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config import Settings
from pipeline.models import AtomicTest

logger = logging.getLogger(__name__)

SSH_TARGET = "huy@192.168.122.115"

STDOUT_LOG = "logs/atomic_stdout.log"

# Timeout tối đa cho mỗi lệnh SSH
TIMEOUT = 130

# Timeout bên trong Atomic Test, chừa thời gian cho cleanup
ATOMIC_TIMEOUT = 100

TECHNIQUE_RE = re.compile(r"T\d{4}(\.\d{3})?")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


def _append_log(text: str) -> None:
    Path(STDOUT_LOG).parent.mkdir(parents=True, exist_ok=True)
    with open(STDOUT_LOG, "a", encoding="utf-8") as f:
        f.write(text)
        f.write("\n")


def _build_remote_script(test: AtomicTest) -> str:
    technique = str(test.technique)
    test_number = int(test.test_number)

    if test_number < 1:
        raise ValueError(f"Invalid test number: {test_number}")
    if not TECHNIQUE_RE.fullmatch(technique):
        raise ValueError(f"Invalid technique ID: {technique}")

    return f'''
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module powershell-yaml
Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1"
$Global:PathToAtomicsFolder = "C:\\AtomicRedTeam\\atomics"
Write-Host "START {technique} Test {test_number}"
Invoke-AtomicTest {technique} -TestNumbers {test_number} -TimeoutSeconds {ATOMIC_TIMEOUT}
$atomicExit = $LASTEXITCODE
Write-Host "END {technique} Test {test_number}"
Invoke-AtomicTest {technique} -TestNumbers {test_number} -CleanUp
exit $atomicExit
'''


def _build_cleanup_script(test: AtomicTest) -> str:
    technique = str(test.technique)
    test_number = int(test.test_number)

    return f'''
Import-Module powershell-yaml
Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1"
$Global:PathToAtomicsFolder = "C:\\AtomicRedTeam\\atomics"
Invoke-AtomicTest {technique} -TestNumbers {test_number} -CleanUp
'''


def _build_ssh_command() -> list[str]:
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        SSH_TARGET,
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
    ]


def _run_remote_script(script: str, timeout: int) -> subprocess.CompletedProcess[str]:
    cmd = _build_ssh_command()
    return subprocess.run(
        cmd,
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_cleanup(test: AtomicTest) -> None:
    technique = test.technique
    test_number = test.test_number
    try:
        result = _run_remote_script(_build_cleanup_script(test), timeout=60)
        _append_log(
            f"[CLEANUP] {technique} Test {test_number}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}\n"
        )
    except Exception:
        logger.exception(
            "Cleanup failed for %s Test %s", technique, test_number
        )


def run_atomic_tests(
    settings: Settings,
    tests: list[AtomicTest],
) -> tuple[str, str]:

    if not tests:
        raise ValueError("No Atomic Tests provided")

    start = _now_iso()
    logger.info("START TIME: %s", start)

    for test in tests:
        technique = test.technique
        test_number = test.test_number

        script = _build_remote_script(test)

        logger.info(
            "Running Atomic Test: %s Test %s",
            technique,
            test_number,
        )

        try:
            result = _run_remote_script(script, timeout=TIMEOUT)

        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")

            _append_log(
                f"[TIMEOUT] {technique} Test {test_number}\n"
                f"STDOUT:\n{stdout}\n"
                f"STDERR:\n{stderr}\n"
            )

            logger.error(
                "Timeout running %s Test %s",
                technique,
                test_number,
            )

            # Thử dọn dẹp dù test đã timeout
            _run_cleanup(test)
            raise

        _append_log(
            f"=== {technique} Test {test_number} ===\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}\n"
            f"EXIT CODE: {result.returncode}\n"
        )

        if result.returncode != 0:
            logger.error(
                "SSH/PowerShell failed for %s Test %s, exit code %d",
                technique,
                test_number,
                result.returncode,
            )
            raise RuntimeError(
                f"{technique} Test {test_number} failed. "
                f"See {STDOUT_LOG} for details."
            )

    end = _now_iso()
    logger.info("END TIME: %s", end)

    return start, end