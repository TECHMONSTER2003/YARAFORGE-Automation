"""Logging: aligned, timestamped, stage-tagged lines to console + file.

Line format (console and file are identical so log excerpts in the report
are verbatim copies of what the analyst saw):

    2026-10-25 14:03:11 | INFO  | triage   | mockbot_v2_a.exe PE32 ...
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

FMT = "%(asctime)s | %(levelname)-5s | %(stage)-8s | %(message)s"
DATEFMT = "%Y-%m-%d %H:%M:%S"


class _StageFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "stage"):
            record.stage = record.name.rsplit(".", 1)[-1][:8]
        return True


def setup(log_file: Path | None, verbose: bool = False) -> None:
    root = logging.getLogger("yaraforge")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    root.propagate = False
    fmt = logging.Formatter(FMT, DATEFMT)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)
    ch.addFilter(_StageFilter())
    root.addHandler(ch)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        fh.addFilter(_StageFilter())
        root.addHandler(fh)


def get(stage: str) -> logging.Logger:
    return logging.getLogger(f"yaraforge.{stage}")
