"""Stand-in for the mingw-w64 cross compilers on Windows hosts (no WSL).

build_corpus.py looks up i686-w64-mingw32-gcc / x86_64-w64-mingw32-gcc on PATH;
the .cmd launchers next to this file forward to `zig cc` (pip package `ziglang`).
lld does not support --no-insert-timestamp, so it is dropped (builds are then not
byte-reproducible, but are otherwise equivalent).

  usage: zigcc.py <zig-target> <gcc args...>
"""
import subprocess
import sys

target, args = sys.argv[1], sys.argv[2:]
args = [a for a in args if a != "-Wl,--no-insert-timestamp"]
# zig enables UBSan at -O0; gcc does not
sys.exit(subprocess.call([sys.executable, "-m", "ziglang", "cc", "-target", target, "-fno-sanitize=undefined", *args]))
