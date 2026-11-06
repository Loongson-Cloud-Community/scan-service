"""Shared acceptance rules for scan events and result reconciliation."""

from typing import Final, Literal


ScanState = Literal["RUNNING", "FINISHED", "FAILED", "NOT_AVAILABLE"]
ScanEvent = Literal["started", "completed", "failed"]

RUNNING: Final = "RUNNING"
FINISHED: Final = "FINISHED"
FAILED: Final = "FAILED"
NOT_AVAILABLE: Final = "NOT_AVAILABLE"
TERMINAL_STATES: Final = frozenset({FINISHED, FAILED})


def is_terminal(state: str) -> bool:
    return state in TERMINAL_STATES


def accepts_event(state: str, event: ScanEvent, *, ended: bool = False) -> bool:
    # Each registered scan identifies one attempt. Replayed callbacks cannot
    # replace a final decision; retrying a scan must use a new Build.
    # NOT_AVAILABLE is provisional and can still accept results when artifacts
    # become readable.
    if is_terminal(state):
        return False
    return event != "started" or not ended


def state_without_results(*, building: bool, ended: bool) -> ScanState:
    # The Jenkins Build may continue after the scan stage has already ended.
    return RUNNING if building and not ended else NOT_AVAILABLE
