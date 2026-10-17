from __future__ import annotations

import logging
import queue
import re
import subprocess
import threading
import time
from pathlib import Path

from pipeline.models import AtomicTest

logger = logging.getLogger(__name__)

SSH_TARGET = "huy@192.168.122.115"
STDOUT_LOG = "logs/atomic_stdout.log"

ATOMIC_TIMEOUT = 100
PER_TEST_BUFFER = 30
SSH_CONNECT_BUFFER = 20
MAX_RECONNECTS = 3

TECHNIQUE_RE = re.compile(r"T\d{4}(\.\d{3})?")

MARKER_READY = "##SESSION_READY##"
MARKER_TEST_START = "##ATOMIC_TEST_START##"
MARKER_TS_START = "##ATOMIC_TS_START##"
MARKER_TS_END = "##ATOMIC_TS_END##"
MARKER_EXIT = "##ATOMIC_EXIT##"
MARKER_TEST_END = "##ATOMIC_TEST_END##"


def _append_log(text: str) -> None:
    Path(STDOUT_LOG).parent.mkdir(parents=True, exist_ok=True)
    with open(STDOUT_LOG, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def _validate(test: AtomicTest) -> tuple[str, int]:
    technique = str(test.technique)
    test_number = int(test.test_number)
    if test_number < 1:
        raise ValueError(f"Invalid test number: {test_number}")
    if not TECHNIQUE_RE.fullmatch(technique):
        raise ValueError(f"Invalid technique ID: {technique}")
    return technique, test_number


def _build_ssh_command() -> list[str]:
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        SSH_TARGET,
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
    ]


class _Hung(Exception):
    """Phiên không phản hồi trong thời gian cho phép."""


class _PSSession:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            _build_ssh_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._q: queue.Queue = queue.Queue()
        self._closed = False
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self) -> None:
        try:
            for line in self.proc.stdout:
                self._q.put(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            self._q.put(None)

    def send(self, script: str) -> None:
        if self._closed:
            raise RuntimeError("Session đã đóng")
        try:
            self.proc.stdin.write(script)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise _Hung() from e

    def readline(self, timeout: float) -> str | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            raise _Hung()

    def close(self, grace: float = 3.0) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass


def _open_session() -> _PSSession:
    session = _PSSession()
    header = f'''
$ErrorActionPreference = "Continue"
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module powershell-yaml
Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1"
$Global:PathToAtomicsFolder = "C:\\AtomicRedTeam\\atomics"
Write-Host "{MARKER_READY}"
'''
    session.send(header)

    deadline = time.monotonic() + SSH_CONNECT_BUFFER
    buf: list[str] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            session.close()
            raise TimeoutError("Timeout khi thiết lập phiên SSH:\n" + "\n".join(buf))
        line = session.readline(remaining)
        if line is None:
            session.close()
            raise RuntimeError("Phiên SSH đóng ngay khi khởi tạo:\n" + "\n".join(buf))
        buf.append(line)
        if MARKER_READY in line:
            return session


def _build_test_block(idx: int, test: AtomicTest) -> str:
    technique, test_number = _validate(test)
    return f'''
Write-Host "{MARKER_TEST_START} {idx} {technique} {test_number}"
$tsStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "{MARKER_TS_START} $tsStart"
$exitCode = 0
try {{
    Invoke-AtomicTest {technique} -TestNumbers {test_number} -TimeoutSeconds {ATOMIC_TIMEOUT}
    if ($LASTEXITCODE) {{ $exitCode = $LASTEXITCODE }}
}} catch {{
    Write-Host "ERROR: $($_.Exception.Message)"
    $exitCode = 1
}} finally {{
    try {{
        Invoke-AtomicTest {technique} -TestNumbers {test_number} -CleanUp
    }} catch {{
        Write-Host "CLEANUP ERROR: $($_.Exception.Message)"
    }}
}}
$tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "{MARKER_TS_END} $tsEnd"
Write-Host "{MARKER_EXIT} $exitCode"
Write-Host "{MARKER_TEST_END} {idx}"
'''


def _run_on_session(session: _PSSession, idx: int, test: AtomicTest) -> dict:
    session.send(_build_test_block(idx, test))
    timeout = ATOMIC_TIMEOUT + PER_TEST_BUFFER
    deadline = time.monotonic() + timeout

    data: dict = {"technique": str(test.technique), "test_number": int(test.test_number)}
    body_lines: list[str] = []
    end_marker = f"{MARKER_TEST_END} {idx}"

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Hung()
        line = session.readline(remaining)
        if line is None:
            raise _Hung()

        if line.startswith(MARKER_TS_START):
            data["ts_start"] = line[len(MARKER_TS_START):].strip()
        elif line.startswith(MARKER_TS_END):
            data["ts_end"] = line[len(MARKER_TS_END):].strip()
        elif line.startswith(MARKER_EXIT):
            data["exit_code"] = int(line[len(MARKER_EXIT):].strip())
        elif line.startswith(end_marker):
            data["body"] = "\n".join(body_lines)
            return data
        else:
            body_lines.append(line)


class AtomicSession:
    """
    1 phiên SSH/PowerShell dùng xuyên suốt nhiều Atomic Test.
    Dùng như context manager:

        with AtomicSession() as runner:
            for test in tests:
                start, end = runner.run_test(test)

    Tự kết nối lại khi phiên bị treo/timeout, thử lại đúng test đang
    chạy dở. Thời gian start/end lấy từ đồng hồ máy đích, trả về và
    cũng được gán thẳng vào test.start_time / test.end_time.
    """

    def __init__(self) -> None:
        self._session: _PSSession | None = None
        self._reconnects = 0
        self._next_idx = 0  # idx tăng dần suốt vòng đời session object,
                             # tránh đụng idx giữa các lần retry

    def __enter__(self) -> "AtomicSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def run_test(self, test: AtomicTest) -> tuple[str, str]:
        technique, test_number = test.technique, test.test_number
        idx = self._next_idx
        self._next_idx += 1

        while True:
            if self._session is None:
                try:
                    self._session = _open_session()
                    if self._reconnects:
                        logger.info("Đã kết nối lại phiên SSH (lần %d)", self._reconnects)
                except Exception:
                    self._reconnects += 1
                    logger.exception(
                        "Không thể mở phiên SSH (lần thử %d/%d)",
                        self._reconnects, MAX_RECONNECTS,
                    )
                    if self._reconnects > MAX_RECONNECTS:
                        raise
                    time.sleep(min(5 * self._reconnects, 30))
                    continue

            logger.info("Running Atomic Test: %s Test %s", technique, test_number)
            try:
                r = _run_on_session(self._session, idx, test)
            except _Hung:
                _append_log(
                    f"[TIMEOUT] {technique} Test {test_number} - phiên không phản hồi, "
                    f"đang kết nối lại.\n"
                )
                logger.error(
                    "Phiên treo khi chạy %s Test %s, đóng phiên và thử kết nối lại",
                    technique, test_number,
                )
                self._session.close()
                self._session = None
                self._reconnects += 1
                if self._reconnects > MAX_RECONNECTS:
                    raise RuntimeError(
                        f"Vượt quá số lần reconnect cho phép ({MAX_RECONNECTS}) tại "
                        f"{technique} Test {test_number}. Xem {STDOUT_LOG}; có thể "
                        f"cần kiểm tra/dọn dẹp thủ công trên máy đích."
                    )
                continue  # thử lại đúng test này trên phiên mới

            test.start_time = r.get("ts_start")
            test.end_time = r.get("ts_end")

            _append_log(
                f"=== {r['technique']} Test {r['test_number']} ===\n"
                f"TS_START: {r.get('ts_start', '?')}\n"
                f"TS_END:   {r.get('ts_end', '?')}\n"
                f"EXIT CODE: {r.get('exit_code', '?')}\n"
                f"STDOUT:\n{r.get('body', '')}\n"
            )

            if r.get("exit_code", 1) != 0:
                logger.error(
                    "Atomic Test %s Test %s thất bại, exit code %s",
                    r["technique"], r["test_number"], r.get("exit_code"),
                )
                raise RuntimeError(
                    f"{r['technique']} Test {r['test_number']} failed. "
                    f"See {STDOUT_LOG} for details."
                )

            return test.start_time, test.end_time