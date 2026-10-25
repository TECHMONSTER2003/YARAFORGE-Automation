"""Stage 1 - triage: identity and structure of a file, without executing it.

Produces hashes, magic-based file type, entropy and (for PE files) header,
section, import and packer-heuristic data via pefile.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover - pefile is a hard requirement for PE features
    pefile = None

PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".nsp0", ".nsp1", ".perplex",
    ".petite", "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1", ".enigma1",
}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
SUBSYSTEMS = {2: "GUI", 3: "Console", 1: "Native"}
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_WRITE = 0x80000000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def magic_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] == b"PK\x03\x04":
        return "ZIP/OOXML"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE2"
    if data[:5] == b"%PDF-":
        return "PDF"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def pe_profile(data: bytes) -> dict:
    """Parse PE structure. Never raises: malformed PEs are common in malware,
    so every failure is captured into the profile as `pe_error`."""
    if pefile is None:
        return {"pe_error": "pefile not installed"}
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception as exc:  # pefile.PEFormatError and friends
        return {"pe_error": f"{type(exc).__name__}: {exc}"}

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is_dll = bool(fh.Characteristics & 0x2000)
    clr_dir = oh.DATA_DIRECTORY[14] if len(oh.DATA_DIRECTORY) > 14 else None
    is_dotnet = bool(clr_dir and clr_dir.VirtualAddress and clr_dir.Size)

    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ch = s.Characteristics
        sections.append({
            "name": name,
            "vsize": s.Misc_VirtualSize,
            "rawsize": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
            "exec": bool(ch & SCN_MEM_EXECUTE),
            "write": bool(ch & SCN_MEM_WRITE),
        })

    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace").lower()
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("latin-1", "replace"))
            else:
                funcs.append(f"ord{imp.ordinal}")
        imports.setdefault(dll, []).extend(funcs)

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                exports.append(e.name.decode("latin-1", "replace"))

    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None

    packer_hints = []
    for s in sections:
        if s["name"] in PACKER_SECTIONS:
            packer_hints.append(f"packer section name {s['name']}")
        if s["exec"] and s["entropy"] > 7.2:
            packer_hints.append(f"high-entropy executable section {s['name']} ({s['entropy']})")
        if s["exec"] and s["write"]:
            packer_hints.append(f"W+X section {s['name']}")
    n_imports = sum(len(v) for v in imports.values())
    if 0 < n_imports < 10 and not is_dotnet:
        packer_hints.append(f"very small import table ({n_imports} functions)")

    prof = {
        "pe_type": ("PE32+" if oh.Magic == 0x20B else "PE32") + (" DLL" if is_dll else " EXE"),
        "dotnet": is_dotnet,
        "machine": MACHINES.get(fh.Machine, hex(fh.Machine)),
        "subsystem": SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
        "timestamp": fh.TimeDateStamp,
        "entrypoint": hex(oh.AddressOfEntryPoint),
        "imphash": imphash,
        "sections": sections,
        "imports": imports,
        "import_count": n_imports,
        "exports": exports[:200],
        "packer_hints": packer_hints,
        "pe_warnings": pe.get_warnings()[:10],
    }
    pe.close()
    return prof


def triage(path: Path, max_size: int) -> tuple[dict, bytes | None]:
    """Return (profile, data). data is None when the file was skipped."""
    st = path.stat()
    prof: dict = {"file": path.name, "path": str(path), "size": st.st_size}
    if st.st_size == 0:
        prof["skipped"] = "empty file"
        return prof, None
    if st.st_size > max_size:
        prof["skipped"] = f"larger than max_file_size ({max_size} bytes)"
        return prof, None
    data = path.read_bytes()
    prof.update(hashes(data))
    prof["type"] = magic_type(data)
    prof["entropy"] = round(shannon_entropy(data), 3)
    if prof["type"] == "PE":
        prof["pe"] = pe_profile(data)
    return prof, data
