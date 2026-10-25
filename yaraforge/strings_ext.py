"""Stage 2 - string extraction.

* static ASCII and UTF-16LE strings (built in, fast - used for goodware too)
* FLOSS decoded / stack / tight strings (family samples only - slow, emulation based)

Every string carries its origin so the rule generator knows how it can be
matched: static strings match as-is, FLOSS *decoded* strings only exist at
runtime, so they are emitted with YARA's `xor` modifier; stack strings are
built instruction-by-instruction and cannot be matched as a byte string at all
(they are reported as IOCs only).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from yaraforge import logutil

log = logutil.get("strings")


def _ascii_re(n: int) -> re.Pattern:
    return re.compile(rb"[\x20-\x7e]{%d,}" % n)


def _wide_re(n: int) -> re.Pattern:
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n)


def static_strings(data: bytes, min_len: int, max_len: int) -> dict[str, set[str]]:
    """Return {'ascii': {...}, 'wide': {...}}."""
    out = {"ascii": set(), "wide": set()}
    for m in _ascii_re(min_len).finditer(data):
        s = m.group().decode("ascii")
        if len(s) <= max_len:
            out["ascii"].add(s)
    for m in _wide_re(min_len).finditer(data):
        s = m.group().decode("utf-16le", "ignore")
        # alignment artefact: the last char of a preceding ASCII string + its NUL
        # terminator looks like one UTF-16 char ("hello_world\0" + L"Wide" -> "dWide")
        if m.start() > 0 and 0x20 <= data[m.start() - 1] < 0x7F:
            s = s[1:]
            if len(s) < min_len:
                continue
        if len(s) <= max_len:
            out["wide"].add(s)
    return out


def floss_strings(path: Path, timeout: int) -> dict:
    """Run FLOSS for decoded, stack and tight strings. Never raises."""
    exe = shutil.which("floss")
    if not exe:
        return {"error": "floss not found on PATH"}
    cmd = [exe, "-q", "-j", "--no", "static", "--", str(path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"floss timeout after {timeout}s"}
    if res.returncode != 0 or not res.stdout.strip():
        err = (res.stderr or "").strip().splitlines()
        return {"error": f"floss exit {res.returncode}: {err[-1] if err else 'no output'}"}
    try:
        doc = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"floss JSON parse error: {exc}"}
    s = doc.get("strings", {})
    return {
        "decoded": sorted({x["string"] for x in s.get("decoded_strings", [])}),
        "stack": sorted({x["string"] for x in s.get("stack_strings", [])}),
        "tight": sorted({x["string"] for x in s.get("tight_strings", [])}),
        "floss_version": doc.get("metadata", {}).get("version"),
    }
