"""Stage 5 - YARA rule synthesis.

Two rules are produced per family:

  <Family>_Strings   - the detection rule: scored family strings, with
                       FLOSS-decoded strings matched via `xor(0x01-0xff)` so the
                       *encoded* bytes on disk are found without knowing the key.
  <Family>_Imports   - a deliberately naive API-only baseline. It exists to be
                       measured against the strings rule (it is expected to
                       false-positive on benign software with the same API use).
"""
from __future__ import annotations

import datetime as dt
import math
import re

import yara

from yaraforge.config import Config
from yaraforge.scoring import Candidate


def _ident(name: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return ident if ident[:1].isalpha() else f"F_{ident}"


def yara_text_string(value: str) -> str:
    """Escape a value for a YARA text string. Non-printables become \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o < 0x100:
            out.append(f"\\x{o:02x}")
        else:
            out.append("?")          # caller filters non-latin values; defensive
    return '"' + "".join(out) + '"'


def _modifiers(c: Candidate) -> str:
    if c.source == "decoded":
        return "xor(0x01-0xff)"
    mods = []
    if "ascii" in c.encodings:
        mods.append("ascii")
    if "wide" in c.encodings:
        mods.append("wide")
    return " ".join(mods or ["ascii"])


def _meta_block(meta: dict) -> str:
    lines = []
    for k, v in meta.items():
        if isinstance(v, bool):
            lines.append(f"        {k} = {'true' if v else 'false'}")
        elif isinstance(v, int):
            lines.append(f"        {k} = {v}")
        else:
            lines.append(f"        {k} = {yara_text_string(str(v))}")
    return "\n".join(lines)


def build_rules(family_name: str, candidates: list[Candidate], imports: list[dict],
                family_profiles: list[dict], attack_ids: list[str], cfg: Config) -> dict:
    """Return {'text': full .yar text, 'strings_rule': name, 'imports_rule': name|None,
    'condition_n': int}. Raises ValueError if nothing usable was selected."""
    if not candidates:
        raise ValueError("no candidate strings survived scoring - cannot build a strings rule")

    fam = _ident(family_name.replace(" ", ""))
    today = dt.date.today().isoformat()
    max_size = max(p.get("size", 0) for p in family_profiles)
    size_limit_kb = max(64, math.ceil(max_size * cfg.filesize_margin / 1024))
    hashes = [p["sha256"] for p in family_profiles if "sha256" in p]
    all_pe = all(p.get("type") == "PE" for p in family_profiles)

    usable = [c for c in candidates if all(ord(ch) < 0x100 for ch in c.value)]
    n_req = max(2, math.ceil(cfg.condition_ratio * len(usable))) if len(usable) > 1 else 1

    str_lines = []
    for i, c in enumerate(usable, 1):
        var = f"$x{i}" if c.source == "decoded" else f"$s{i}"
        comment = f"cov={c.coverage:.2f} src={c.source}" + (f" ioc={c.ioc}" if c.ioc else "")
        str_lines.append(f"        {var} = {yara_text_string(c.value)} {_modifiers(c)}  // {comment}")

    has_s = any(c.source != "decoded" for c in usable)
    has_x = any(c.source == "decoded" for c in usable)
    string_set = ", ".join(v for v, ok in (("$s*", has_s), ("$x*", has_x)) if ok)

    header = "import \"pe\"\n\n" if (imports and all_pe) else ""
    magic = "uint16(0) == 0x5A4D and " if all_pe else ""

    meta = {
        "description": f"Detects {family_name} family samples (auto-generated, strings rule)",
        "author": cfg.author,
        "date": today,
        "family": family_name,
        "generator": "yaraforge 1.0.0",
        "sample_count": len(family_profiles),
        "attack": ", ".join(attack_ids) if attack_ids else "n/a",
        "hash1": hashes[0] if hashes else "n/a",
    }
    if len(hashes) > 1:
        meta["hash2"] = hashes[1]

    strings_rule = f"{fam}_Strings"
    text = header
    text += (
        f"rule {strings_rule}\n{{\n    meta:\n{_meta_block(meta)}\n\n"
        f"    strings:\n" + "\n".join(str_lines) + "\n\n"
        f"    condition:\n        {magic}filesize < {size_limit_kb}KB and\n"
        f"        {n_req} of ({string_set})\n}}\n"
    )

    imports_rule = None
    if imports and all_pe:
        imports_rule = f"{fam}_Imports_Baseline"
        conds = []
        for imp in imports:
            dll, fn = imp["import"].split("!", 1)
            conds.append(f"pe.imports(/{re.escape(dll)}/i, /^{re.escape(fn)}$/i)")
        imeta = {
            "description": f"{family_name} API-only baseline - for comparison, NOT for deployment",
            "author": cfg.author,
            "date": today,
            "quality": "low",
        }
        text += (
            f"\nrule {imports_rule}\n{{\n    meta:\n{_meta_block(imeta)}\n\n"
            f"    condition:\n        uint16(0) == 0x5A4D and\n        "
            + " and\n        ".join(conds) + "\n}\n"
        )

    yara.compile(source=text)    # raises yara.SyntaxError -> caller logs and aborts
    return {"text": text, "strings_rule": strings_rule, "imports_rule": imports_rule,
            "condition_n": n_req, "string_count": len(usable), "size_limit_kb": size_limit_kb}
