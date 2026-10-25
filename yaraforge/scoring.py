"""Stage 4 - candidate selection: which strings identify THIS family and nothing else.

Decision path for every string (each rejection is counted and logged):

    length / noise filter  -> stoplist (compiler, runtime boilerplate)
    -> family coverage     (in >= min_coverage of family samples?)
         \-- low coverage  -> prefix generalisation (defeats builder randomisation,
                              e.g. "MKBCFG::v2::build=a1b2c3" -> "MKBCFG::v2::build=")
    -> goodware exact-set check (cheap)
    -> score  = 0.6*coverage + 0.2*length_factor + 0.2*ioc_class
    -> goodware raw-substring check on the top N (YARA matches substrings,
       so a string that is *inside* a goodware string is still a false positive)
    -> diversity selection (drop strings that are substrings of a selected one)
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from yaraforge import logutil
from yaraforge.config import Config

log = logutil.get("scoring")

IOC_PATTERNS = {
    "url": re.compile(r"^[a-z][a-z0-9+.-]{1,9}://\S+", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-z0-9-]{2,63}\.(?:com|net|org|info|biz|ru|cn|top|xyz|io|invalid|onion)\b", re.I),
    "registry": re.compile(r"^(HK(LM|CU|EY_)|Software\\|SYSTEM\\)", re.I),
    "mutex": re.compile(r"^(Global|Local)\\", re.I),
    "user_agent": re.compile(r"^Mozilla/\d\.\d", re.I),
    "filepath": re.compile(r"^([A-Z]:\\|%[A-Z]+%\\|\\\\)", re.I),
    "config_marker": re.compile(r"[A-Z]{3,}::|::[a-z0-9]+=|\bcfg\b|config", re.I),
    "email": re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,6}\b"),
}
PREFIX_DELIMS = set("=:/\\_-.?& ")


def ioc_class(s: str) -> str | None:
    for name, rx in IOC_PATTERNS.items():
        if rx.search(s):
            return name
    return None


def is_noise(s: str) -> str | None:
    """Return a rejection reason for structurally useless strings, else None."""
    if len(set(s)) / len(s) < 0.25 and len(s) >= 8:
        return "low_diversity"
    alnum = sum(c.isalpha() for c in s)
    if alnum == 0:
        return "no_letters"
    junk = sum((c.isdigit() or c in ",.;:-+ ") for c in s)
    if junk / len(s) > 0.7:
        return "mostly_digits_punct"
    return None


@dataclass
class Candidate:
    value: str
    source: str                         # static | decoded | prefix
    encodings: set = field(default_factory=set)   # ascii / wide / xor
    samples: set = field(default_factory=set)
    coverage: float = 0.0
    goodware_hits: int = 0
    ioc: str | None = None
    score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "value": self.value, "source": self.source,
            "encodings": sorted(self.encodings), "samples": sorted(self.samples),
            "coverage": round(self.coverage, 3), "goodware_hits": self.goodware_hits,
            "ioc": self.ioc, "score": round(self.score, 4),
        }


class GoodwareIndex:
    """Goodware baseline: exact string set + raw blobs for substring checks."""

    def __init__(self) -> None:
        self.strings: Counter = Counter()   # string -> number of goodware files containing it
        self.blobs: list[tuple[str, bytes]] = []
        self.import_df: Counter = Counter() # "dll!func" -> number of goodware PEs importing it
        self.pe_count = 0
        self.file_count = 0

    def add(self, name: str, data: bytes, strings: dict[str, set[str]], imports: dict | None) -> None:
        self.file_count += 1
        self.blobs.append((name, data))
        for s in strings["ascii"] | strings["wide"]:
            self.strings[s] += 1
        if imports is not None:
            self.pe_count += 1
            for key in {f"{dll}!{fn}".lower() for dll, fns in imports.items() for fn in fns}:
                self.import_df[key] += 1

    def substring_hits(self, value: str, encodings: set) -> list[str]:
        pats = []
        if "ascii" in encodings or "xor" in encodings:
            pats.append(value.encode("latin-1", "ignore"))
        if "wide" in encodings:
            pats.append(value.encode("utf-16le"))
        return [name for name, blob in self.blobs if any(p and p in blob for p in pats)]


def _prefixes(s: str, min_len: int) -> list[str]:
    """Prefixes that end on a delimiter, e.g. 'A::b=xyz' -> ['A::', 'A::b=']."""
    return [s[: i + 1] for i, c in enumerate(s) if c in PREFIX_DELIMS and i + 1 >= min_len and i + 1 < len(s)]


def select_candidates(family: dict[str, dict], gw: GoodwareIndex, cfg: Config,
                      quiet: bool = False) -> tuple[list[Candidate], dict]:
    """family: {sample_name: features}. Returns (selected candidates, stats)."""
    n = len(family)
    stoplist = [re.compile(p) for p in cfg.stoplist_regex]
    rejected: Counter = Counter()
    pool: dict[tuple[str, str], Candidate] = {}

    # ---- collect per-sample string occurrences -------------------------------------
    for name, feat in family.items():
        st = feat["strings"]
        static_all = set(st["ascii"]) | set(st["wide"])
        for enc in ("ascii", "wide"):
            for s in st[enc]:
                c = pool.setdefault((s, "static"), Candidate(s, "static"))
                c.encodings.add(enc)
                c.samples.add(name)
        for s in feat.get("floss", {}).get("decoded", []):
            if s in static_all:          # FLOSS re-reporting a plain string
                continue
            c = pool.setdefault((s, "decoded"), Candidate(s, "decoded"))
            c.encodings.add("xor")
            c.samples.add(name)

    total_unique = len(pool)
    low_cov_static: dict[str, set] = defaultdict(set)   # value -> samples (for prefix generalisation)
    survivors: list[Candidate] = []

    for (s, src), c in pool.items():
        if not (cfg.min_string_len <= len(s) <= cfg.max_string_len):
            rejected["length"] += 1
            continue
        if any(rx.search(s) for rx in stoplist):
            rejected["stoplist"] += 1
            continue
        reason = is_noise(s)
        if reason:
            rejected[reason] += 1
            continue
        c.coverage = len(c.samples) / n
        if c.coverage < cfg.min_coverage:
            rejected["low_coverage"] += 1
            if src == "static":
                low_cov_static[s] |= c.samples
            continue
        gw_hits = gw.strings.get(s, 0)
        if gw_hits > cfg.max_goodware_hits:
            rejected["goodware_exact"] += 1
            if ioc_class(s) and not quiet:     # a family-wide IOC-looking string that legit software also has
                log.info("reject IOC-like string also in %d goodware file(s): %r", gw_hits, s)
            continue
        survivors.append(c)

    # ---- prefix generalisation over low-coverage strings ----------------------------
    prefix_samples: dict[str, set] = defaultdict(set)
    for s, samples in low_cov_static.items():
        for p in _prefixes(s, cfg.prefix_min_len):
            prefix_samples[p] |= samples
    exact_values = {c.value for c in survivors}
    prefix_kept: list[Candidate] = []
    for p in sorted(prefix_samples, key=len, reverse=True):
        cov = len(prefix_samples[p]) / n
        if cov < cfg.min_coverage or is_noise(p) or any(rx.search(p) for rx in stoplist):
            continue
        if p in exact_values or any(e.startswith(p) for e in exact_values):
            continue
        if any(k.value.startswith(p) and k.coverage >= cov for k in prefix_kept):
            continue                     # a longer prefix already covers the same samples
        if gw.strings.get(p, 0) > cfg.max_goodware_hits:
            rejected["goodware_exact"] += 1
            continue
        c = Candidate(p, "prefix", {"ascii"}, set(prefix_samples[p]), cov)
        prefix_kept.append(c)
    survivors.extend(prefix_kept)

    # ---- drop static strings that are just the on-disk XOR form of a decoded string ---
    # (the decoded string is emitted with the `xor` modifier, which already covers them)
    decoded_vals = [c.value.encode("latin-1", "ignore") for c in survivors if c.source == "decoded"]
    if decoded_vals:
        enc_forms = [bytes(b ^ k for b in v) for v in decoded_vals for k in range(1, 256)]
        kept = []
        for c in survivors:
            if c.source != "decoded":
                b = c.value.encode("latin-1", "ignore")
                if len(b) >= 6 and any(b in e for e in enc_forms):
                    rejected["xor_encoded_form_of_decoded"] += 1
                    continue
            kept.append(c)
        survivors = kept

    # ---- score ------------------------------------------------------------------------
    for c in survivors:
        c.ioc = ioc_class(c.value)
        c.score = 0.6 * c.coverage + 0.2 * min(len(c.value), 32) / 32 + 0.2 * (1 if c.ioc else 0)
    survivors.sort(key=lambda c: (-c.score, -len(c.value), c.value))

    # ---- goodware raw-substring verification on the top N ---------------------------
    verified: list[Candidate] = []
    for c in survivors[: cfg.substring_verify_top]:
        hits = gw.substring_hits(c.value, c.encodings)
        c.goodware_hits = len(hits)
        if c.goodware_hits > cfg.max_goodware_hits:
            rejected["goodware_substring"] += 1
            log.debug("reject (goodware substring in %s): %r", ",".join(hits[:3]), c.value)
            continue
        verified.append(c)

    # ---- diversity selection --------------------------------------------------------
    selected: list[Candidate] = []
    for c in verified:
        if any(c.value in s.value or s.value in c.value for s in selected):
            rejected["redundant_substring"] += 1
            continue
        selected.append(c)
        if len(selected) >= cfg.max_rule_strings:
            break

    stats = {
        "unique_strings": total_unique,
        "survivors_before_verify": len(survivors),
        "prefix_generalised": len(prefix_kept),
        "verified": len(verified),
        "selected": len(selected),
        "rejected": dict(rejected),
    }
    return selected, stats


# Imports pulled in by the C runtime / compiler (locale, printf, string conversion).
# They describe the toolchain, not the program's behaviour, so the API baseline ignores them.
CRT_NOISE_IMPORTS = {
    "isdbcsleadbyteex", "multibytetowidechar", "widechartomultibyte", "getstringtypew",
    "lcmapstringw", "getcpinfo", "getacp", "getoemcp", "___lc_codepage_func", "__mb_cur_max",
    "_isctype", "localeconv", "setlocale",
}


def select_imports(family: dict[str, dict], gw: GoodwareIndex, max_imports: int = 4) -> list[dict]:
    """Imports present in every family PE, ranked by rarity in goodware.
    Used for the *baseline* import rule that demonstrates why API-only rules FP."""
    sets = []
    for feat in family.values():
        imps = feat["profile"].get("pe", {}).get("imports")
        if imps is None:
            continue
        sets.append({f"{dll}!{fn}".lower() for dll, fns in imps.items() for fn in fns})
    if not sets:
        return []
    common = set.intersection(*sets)
    ranked = []
    for key in common:
        if key.split("!", 1)[1] in CRT_NOISE_IMPORTS:
            continue
        ratio = gw.import_df.get(key, 0) / max(gw.pe_count, 1)
        ranked.append({"import": key, "goodware_ratio": round(ratio, 3)})
    ranked.sort(key=lambda d: (d["goodware_ratio"], d["import"]))
    return [r for r in ranked if r["goodware_ratio"] <= 0.25][:max_imports]
