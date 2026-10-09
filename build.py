#!/usr/bin/env python3
"""
Build IPTV Scanner + VPN helper with automatic hash insertion.
"""
from __future__ import annotations
import hashlib
import re
import subprocess
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VPN_SRC = ROOT / "vpn.py"
VPN_EXE = ROOT / "dist" / "vpn.exe"          # default PyInstaller path
SCANNER_SRC = ROOT / "IPTV_scanner.pyw"

# Pattern to search/replace (must match the source)
HASH_PATTERN = re.compile(
    r'^(EXPECTED_VPN_HELPER_SHA256\s*:\s*str\s*=\s*)([\'"])[^\'"]*\2',
    re.MULTILINE,
)

def run(cmd: list[str], **kwargs) -> None:
    print(">>", " ".join(cmd))
    subprocess.check_call(cmd, **kwargs)

def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def patch_expected_hash(src: Path, new_hash: str) -> None:
    text = src.read_text(encoding="utf-8")
    new_text, n = HASH_PATTERN.subn(rf'\1"{new_hash}"', text, count=1)
    if n != 1:
        raise RuntimeError(
            f"Не удалось найти/заменить EXPECTED_VPN_HELPER_SHA256 в {src}. "
            "Проверь, что константа объявлена в ожидаемом виде."
        )
    src.write_text(new_text, encoding="utf-8")
    print(f"Вписан хеш {new_hash} → {src.name}")

def main() -> int:
    # 1. Reset hash
    original = VPN_SRC.read_text(encoding="utf-8")
    if 'EXPECTED_VPN_HELPER_SHA256: str = ""' not in original and \
       'EXPECTED_VPN_HELPER_SHA256: str = \'\'' not in original:
        patch_expected_hash(VPN_SRC, "")

    dist_dir = ROOT / "dist"
    build_dir = ROOT / "build"

    # 2. Build vpn.exe
    run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "vpn",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        str(VPN_SRC),
    ])

    if not VPN_EXE.exists():
        print("Ошибка: vpn.exe не появился", file=sys.stderr)
        return 1

    # 3. Compute hash
    digest = compute_sha256(VPN_EXE)
    print(f"SHA-256 vpn.exe = {digest}")

    # 4. Write hash back into vpn.py
    patch_expected_hash(VPN_SRC, digest)

    # 5. Build the main scanner

    run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "IPTV_Scanner",
        "--hidden-import", "vpn",
        "--hidden-import", "truststore",
        "--add-data", f"{VPN_SRC}{os.pathsep}.",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        str(SCANNER_SRC),
    ])

    print("\nГотово.")
    print(f"  vpn.exe          → {VPN_EXE}")
    print(f"  IPTV_Scanner.exe → {dist_dir / 'IPTV_Scanner.exe'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())