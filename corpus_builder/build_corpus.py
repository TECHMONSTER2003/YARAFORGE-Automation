#!/usr/bin/env python3
"""Build the harmless lab corpus.

Outputs
  <out>/family/mockbot/   simulated malware family (benign PE builds)
  <out>/clean/            goodware: benign mingw builds (+ optional extra PE dirs)
  <out>/manifest.json     what was built, with which options

Family members vary in: architecture (x86/x64), optimisation level,
per-build junk strings, XOR key. One deliberately "drifted" variant
changes mutex + user agent to test rule robustness against version drift.

Usage
  python3 build_corpus.py --out ./corpus --extra-clean /path/to/pe/dir
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clean_sources import CLEAN_PROGRAMS  # noqa: E402

HERE = Path(__file__).resolve().parent
TEMPLATE = (HERE / "mockbot_template.c").read_text()

COMPILERS = {"x86": "i686-w64-mingw32-gcc", "x64": "x86_64-w64-mingw32-gcc"}

C2_URL = "http://c2.mockbot.invalid/gate.php?id="          # RFC 2606 reserved TLD
STD_TRAITS = {
    "mutex": "Global\\\\MkB_7f3a9c21",
    "ua": "Mozilla/4.0 (compatible; MkBot/2.1; lab)",
    "cfg": "MKBCFG::v2::build=",
}
DRIFT_TRAITS = {                                           # v3 builder: mutex + UA changed
    "mutex": "Global\\\\MkB3_e01d44",
    "ua": "Mozilla/5.0 (compatible; MkBot/3.0; lab)",
    "cfg": "MKBCFG::v2::build=",                            # config marker survives
}

# (name, arch, opt, traits, xor_key)
FAMILY_PLAN = [
    ("mockbot_v2_a", "x86", "-O0", STD_TRAITS, 0x5A),
    ("mockbot_v2_b", "x86", "-O2", STD_TRAITS, 0x5A),
    ("mockbot_v2_c", "x64", "-O0", STD_TRAITS, 0x5A),
    ("mockbot_v2_d", "x64", "-O2", STD_TRAITS, 0x5A),
    ("mockbot_v2_e", "x86", "-Os", STD_TRAITS, 0x37),
    ("mockbot_v2_f", "x64", "-Os", STD_TRAITS, 0x37),
    ("mockbot_v2_g", "x64", "-O1", STD_TRAITS, 0x5A),
    ("mockbot_v3_drift", "x64", "-O2", DRIFT_TRAITS, 0x6B),
]


def _rand_word(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def render_family(name: str, traits: dict, key: int, rng: random.Random) -> str:
    enc = bytes(b ^ key for b in C2_URL.encode())
    junk = ", ".join(f'"{_rand_word(rng, rng.randint(10, 24))}"' for _ in range(rng.randint(4, 9)))
    src = TEMPLATE
    repl = {
        "@@MUTEX@@": traits["mutex"],
        "@@UA@@": traits["ua"],
        "@@CFG@@": traits["cfg"] + _rand_word(rng, 6),
        "@@JUNK@@": junk,
        "@@XORKEY@@": hex(key),
        "@@ENC_C2@@": ", ".join(hex(b) for b in enc),
        "@@ENC_LEN@@": str(len(enc)),
    }
    for k, v in repl.items():
        src = src.replace(k, v)
    return src


def compile_c(src: str, out_exe: Path, arch: str, opt: str, workdir: Path) -> None:
    cc = shutil.which(COMPILERS[arch])
    if not cc:
        raise SystemExit(f"missing cross compiler {COMPILERS[arch]} (apt install mingw-w64)")
    c_file = workdir / (out_exe.stem + ".c")
    c_file.write_text(src)
    cmd = [cc, opt, "-s", "-Wl,--no-insert-timestamp", "-o", str(out_exe), str(c_file), "-lwininet", "-ladvapi32"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(f"compile failed for {out_exe.name}:\n{res.stderr}")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--extra-clean", action="append", default=[], type=Path,
                    help="directory of extra benign PE files (exe/dll/pyd) to add to clean set")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    fam_dir = args.out / "family" / "mockbot"
    clean_dir = args.out / "clean"
    src_dir = args.out / "_src"
    for d in (fam_dir, clean_dir, src_dir):
        d.mkdir(parents=True, exist_ok=True)

    manifest = {"seed": args.seed, "family": [], "clean": []}

    for name, arch, opt, traits, key in FAMILY_PLAN:
        exe = fam_dir / f"{name}.exe"
        compile_c(render_family(name, traits, key, rng), exe, arch, opt, src_dir)
        manifest["family"].append({"file": exe.name, "arch": arch, "opt": opt,
                                   "xor_key": hex(key), "drift": traits is DRIFT_TRAITS,
                                   "sha256": sha256(exe)})
        print(f"[family] {exe.name:<24} {arch} {opt:<4} key={hex(key)}")

    for prog, src in CLEAN_PROGRAMS.items():
        for arch in ("x86", "x64"):
            exe = clean_dir / f"clean_{prog}_{arch}.exe"
            compile_c(src, exe, arch, "-O2", src_dir)
            manifest["clean"].append({"file": exe.name, "origin": "mingw", "sha256": sha256(exe)})
            print(f"[clean ] {exe.name}")

    seen = {e["sha256"] for e in manifest["clean"]}
    for extra in args.extra_clean:
        for p in sorted(extra.rglob("*")):
            if p.suffix.lower() not in {".exe", ".dll", ".pyd"} or not p.is_file():
                continue
            h = sha256(p)
            if h in seen:
                continue
            seen.add(h)
            dst = clean_dir / f"gw_{h[:10]}_{p.name}"
            shutil.copy2(p, dst)
            manifest["clean"].append({"file": dst.name, "origin": str(p.parent.name), "sha256": h})
    print(f"[clean ] total clean files: {len(manifest['clean'])}")

    shutil.rmtree(src_dir)  # keep corpus dir clean; sources are reproducible from seed
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
