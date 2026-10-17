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
TIMEOUT = 9000

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


def _build_remote_script(tests: list[AtomicTest]) -> str:
    test_entries = ",\n".join(
        f"@{{ Technique = '{test.technique}'; Number = {int(test.test_number)} }}"
        for test in tests
    )
    return f'''
Write-Output "__SCRIPT_STARTED__"
$ErrorActionPreference = "Stop"
Set-ExecutionPolicy Bypass -Scope Process -Force

try {{
    Import-Module powershell-yaml -ErrorAction Stop
    Write-Output "__YAML_IMPORTED__"
    Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1" -ErrorAction Stop
    Write-Output "__ATOMIC_MODULE_IMPORTED__"
}} catch {{
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}}

$Global:PathToAtomicsFolder = "C:\\AtomicRedTeam\\atomics"
$tests = @(
{test_entries}
)

Write-Output "__TEST_COUNT__|$($tests.Count)"

foreach ($test in $tests) {{
    $technique = $test.Technique
    $number = $test.Number
    $start = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Output "__ATOMIC_START__|$technique|$number|$start"
    $status = "completed"

    try {{
        Invoke-AtomicTest $technique -TestNumbers $number -TimeoutSeconds {ATOMIC_TIMEOUT} -ErrorAction Stop
    }} catch {{
        $status = "failed"
        [Console]::Error.WriteLine("__ATOMIC_ERROR__|$technique|$number|$($_.Exception.Message)")
    }}

    $end = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Output "__ATOMIC_END__|$technique|$number|$end|$status"

    try {{
        Invoke-AtomicTest $technique -TestNumbers $number -CleanUp -ErrorAction Stop
    }} catch {{
        [Console]::Error.WriteLine("__ATOMIC_CLEANUP_ERROR__|$technique|$number|$($_.Exception.Message)")
    }}

}}

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



def _run_remote_script(script: str, timeout: int):
    cmd = _build_ssh_command()
    output = []

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        proc.stdin.write(script)
        proc.stdin.close()

        for line in proc.stdout:
            print(line, end="", flush=True)
            output.append(line)

        returncode = proc.wait(timeout=timeout)
        return subprocess.CompletedProcess(
            cmd, returncode, stdout="".join(output), stderr=""
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        if proc.stdout:
            proc.stdout.close()



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


def run_atomic_tests(settings: Settings, tests: list[AtomicTest]) -> dict[tuple[str, int], dict[str, str]]:
    if not tests:
        raise ValueError("No Atomic Tests provided")

    script = _build_remote_script(tests)

    result = _run_remote_script(script, timeout=TIMEOUT)

    _append_log(
        f"=== ATOMIC BATCH ===\nSTDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}\nEXIT CODE: {result.returncode}"
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Atomic batch failed or script did not start. See {STDOUT_LOG}"
        )

    timings: dict[tuple[str, int], dict[str, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split("|")
        if parts[0] == "__ATOMIC_START__" and len(parts) == 4:
            key = (parts[1], int(parts[2]))
            timings.setdefault(key, {})["start_time"] = parts[3]
        elif parts[0] == "__ATOMIC_END__" and len(parts) == 5:
            key = (parts[1], int(parts[2]))
            timings.setdefault(key, {}).update({
                "end_time": parts[3],
                "status": parts[4],
            })
        elif parts[0] == "__ATOMIC_ERROR__":
            logger.error("Atomic test error: %s", line)
        elif parts[0] == "__ATOMIC_CLEANUP_ERROR__":
            logger.warning("Atomic cleanup error: %s", line)

    for test in tests:
        key = (str(test.technique), int(test.test_number))
        if key not in timings or "start_time" not in timings[key] or "end_time" not in timings[key]:
            logger.error("Missing time markers for %s Test %s", *key)

    return timings