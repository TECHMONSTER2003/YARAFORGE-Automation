"""Stage 3 - capability detection with capa, mapped to MITRE ATT&CK and MBC."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def run_capa(path: Path, rules: str | None, sigs: str | None, timeout: int) -> dict:
    """Run capa in JSON mode. Never raises; failure is returned as {'error': ...}.

    capa refuses packed / unsupported files with a non-zero exit code - that is
    an analysis *finding* (likely packed), so it is surfaced, not hidden.
    """
    exe = shutil.which("capa")
    if not exe:
        return {"error": "capa not found on PATH"}
    cmd = [exe, "-q", "-j"]
    if rules:
        cmd += ["-r", rules]
    if sigs:
        cmd += ["-s", sigs]
    cmd += ["--", str(path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"capa timeout after {timeout}s"}
    if res.returncode != 0 or not res.stdout.strip():
        err = (res.stderr or "").strip().splitlines()
        return {"error": f"capa exit {res.returncode}: {err[-1] if err else 'no output'}"}
    try:
        doc = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"capa JSON parse error: {exc}"}

    caps = []
    for name, r in sorted(doc.get("rules", {}).items()):
        meta = r.get("meta", {})
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        caps.append({
            "name": name,
            "namespace": meta.get("namespace"),
            "attack": [
                {"id": a.get("id"), "tactic": a.get("tactic"),
                 "technique": a.get("technique"), "subtechnique": a.get("subtechnique") or ""}
                for a in meta.get("attack", [])
            ],
            "mbc": [f"{m.get('objective')}::{m.get('behavior')} [{m.get('id')}]" for m in meta.get("mbc", [])],
            "match_count": len(r.get("matches", [])),
        })
    return {"capabilities": caps, "capa_version": doc.get("meta", {}).get("version")}
