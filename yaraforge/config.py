"""Central tunables. Every threshold used in a decision lives here so the
report can print the exact configuration that produced a rule."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Config:
    # --- safety / input limits ---
    max_file_size: int = 50 * 1024 * 1024        # skip anything larger (bytes)
    # --- string extraction ---
    min_string_len: int = 6
    max_string_len: int = 200
    # --- external tools ---
    use_floss: bool = True
    floss_timeout: int = 600                      # seconds per sample
    use_capa: bool = True
    capa_timeout: int = 600
    capa_rules: str | None = None                 # path to capa rules dir
    capa_sigs: str | None = None                  # path to capa FLIRT sigs dir
    workers: int = 2                              # parallel sample analysis
    # --- candidate scoring ---
    min_coverage: float = 0.5                     # fraction of family samples a string must appear in
    max_goodware_hits: int = 0                    # strict: string must never appear in goodware
    max_rule_strings: int = 12
    prefix_min_len: int = 8                       # shortest generalised prefix kept
    substring_verify_top: int = 300               # candidates re-checked as raw substrings in goodware
    # --- rule synthesis ---
    condition_ratio: float = 0.5                  # "N of them" = ceil(ratio * #strings), min 2
    filesize_margin: float = 2.0                  # filesize < max_family_size * margin
    author: str = "yaraforge"
    # --- noise filter (compiler/runtime boilerplate) ---
    stoplist_regex: list[str] = field(default_factory=lambda: [
        r"^GCC: \(",
        r"mingw", r"libgcc", r"__[A-Za-z_]+__",
        r"This program cannot be run in DOS mode",
        r"^[A-Za-z0-9_]+\.(dll|DLL|exe|EXE)$",
        r"^(Unknown error|Argument domain error|Overflow range error|Partial loss of significance)",
        r"^_+[A-Za-z]",
        r"^\.(text|data|rdata|bss|idata|edata|pdata|xdata|reloc|rsrc|tls|CRT)",
        r"^[\x20-\x7e]?$",
        r"^(.)\1{4,}$",                           # AAAAAA / ======
        r"^[A-Fa-f0-9]{1,8}$",
    ])

    def as_dict(self) -> dict:
        return asdict(self)
