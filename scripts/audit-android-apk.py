#!/usr/bin/env python3
"""
Portable static APK, ELF/ABI, and 16 KB page-alignment auditor for WireGuard Plus.
Uses Python 3 standard library only so it runs identically on Windows and Linux CI.
"""

from __future__ import annotations

import argparse
import glob
import pathlib
import struct
import sys
import zipfile
from typing import Dict, List, Optional, Tuple

EXPECTED_MACHINE_BY_ABI: Dict[str, Tuple[int, int]] = {
    # abi: (e_machine, expected_ei_class)
    "arm64-v8a": (183, 2),    # EM_AARCH64, ELFCLASS64
    "armeabi-v7a": (40, 1),   # EM_ARM, ELFCLASS32
    "armeabi": (40, 1),       # EM_ARM, ELFCLASS32
    "x86_64": (62, 2),        # EM_X86_64, ELFCLASS64
    "x86": (3, 1),            # EM_386, ELFCLASS32
}

REQUIRED_CORE_SO = ("libgojni.so",)
KNOWN_APP_SO = ("libgojni.so", "libconscrypt_jni.so", "libspake2.so")
PAGE_16KB = 0x4000
PAGE_4KB = 0x1000
PT_LOAD = 1


def parse_elf_info(data: bytes) -> Tuple[int, int, List[int]]:
    """Parse ELF header and PT_LOAD p_align values from raw .so bytes."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not a valid ELF binary (bad magic or truncated)")

    ei_class = data[4]
    ei_data = data[5]
    if ei_data != 1:
        raise ValueError(f"unsupported ELF endianness ei_data={ei_data}")

    if ei_class == 1:
        # ELF32 header: e_machine(H @18), e_phoff(I @28), e_phentsize(H @42), e_phnum(H @44)
        e_machine = struct.unpack_from("<H", data, 18)[0]
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_phentsize = struct.unpack_from("<H", data, 42)[0]
        e_phnum = struct.unpack_from("<H", data, 44)[0]
    elif ei_class == 2:
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        # ELF64 header: e_machine(H @18), e_phoff(Q @32), e_phentsize(H @54), e_phnum(H @56)
        e_machine = struct.unpack_from("<H", data, 18)[0]
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_phentsize = struct.unpack_from("<H", data, 54)[0]
        e_phnum = struct.unpack_from("<H", data, 56)[0]
    else:
        raise ValueError(f"unsupported ELF class ei_class={ei_class}")

    load_aligns: List[int] = []
    for idx in range(e_phnum):
        off = e_phoff + idx * e_phentsize
        if off + e_phentsize > len(data):
            raise ValueError(f"program header {idx} out of bounds")
        if ei_class == 1:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_align = struct.unpack_from("<I", data, off + 28)[0]
        else:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_align = struct.unpack_from("<Q", data, off + 48)[0]
        if p_type == PT_LOAD:
            load_aligns.append(p_align)

    if not load_aligns:
        raise ValueError("no PT_LOAD program headers found")

    return ei_class, e_machine, load_aligns


def infer_expected_abis(apk_path: pathlib.Path, explicit: Optional[str]) -> List[str]:
    if explicit:
        return [a.strip() for a in explicit.split(",") if a.strip()]
    name = apk_path.name.lower()
    if "-arm64-v8a" in name:
        return ["arm64-v8a"]
    if "-armeabi-v7a" in name:
        return ["armeabi-v7a"]
    if "-x86_64" in name:
        return ["x86_64"]
    return ["arm64-v8a", "armeabi-v7a"]


def format_align(align_bytes: int) -> str:
    if align_bytes >= 1024 and align_bytes % 1024 == 0:
        return f"{align_bytes // 1024} KB (0x{align_bytes:x})"
    return f"{align_bytes} B (0x{align_bytes:x})"


def audit_apk(
    apk_path: pathlib.Path,
    expected_abis: List[str],
    strict_16kb: bool,
) -> Tuple[bool, int]:
    """Audit one APK. Returns (passed_hard_checks, warning_count)."""
    if not apk_path.is_file():
        print(f"[FAIL] APK not found: {apk_path}")
        return False, 0

    hard_fail = False
    warnings = 0
    size_mb = apk_path.stat().st_size / (1024.0 * 1024.0)
    print(f"\n=== Auditing APK: {apk_path} ({size_mb:.2f} MiB) ===")
    print(f"Expected ABIs: {', '.join(expected_abis)}")

    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()
        dex_files = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
        has_manifest = "AndroidManifest.xml" in names

        if not has_manifest:
            print("  [FAIL] Missing AndroidManifest.xml")
            hard_fail = True
        if not dex_files:
            print("  [FAIL] Missing classes*.dex")
            hard_fail = True
        else:
            print(f"  [PASS] DEX & Manifest present ({len(dex_files)} dex file(s))")

        so_entries: Dict[str, Dict[str, zipfile.ZipInfo]] = {}
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                so_entries.setdefault(parts[1], {})[parts[2]] = info

        # Check expected ABIs exist and contain required core .so
        for abi in expected_abis:
            libs = so_entries.get(abi, {})
            if not libs:
                print(f"  [FAIL] Missing expected ABI directory lib/{abi}/")
                hard_fail = True
                continue
            for core_lib in REQUIRED_CORE_SO:
                if core_lib not in libs:
                    print(f"  [FAIL] Missing {core_lib} in lib/{abi}/")
                    hard_fail = True
            for known in KNOWN_APP_SO:
                if known not in libs:
                    print(f"  [WARN] Optional/third-party {known} absent in lib/{abi}/")
                    warnings += 1

        # Audit all .so entries found across all ABIs in the APK
        print("  Native ELF & Alignment Matrix:")
        for abi in sorted(so_entries.keys()):
            exp_spec = EXPECTED_MACHINE_BY_ABI.get(abi)
            for so_name in sorted(so_entries[abi].keys()):
                info = so_entries[abi][so_name]
                raw = zf.read(info.filename)
                try:
                    ei_class, e_machine, load_aligns = parse_elf_info(raw)
                except ValueError as exc:
                    print(f"    [FAIL] lib/{abi}/{so_name}: corrupt/invalid ELF ({exc})")
                    hard_fail = True
                    continue

                if exp_spec is not None:
                    exp_machine, exp_class = exp_spec
                    if e_machine != exp_machine or ei_class != exp_class:
                        print(
                            f"    [FAIL] lib/{abi}/{so_name}: ABI mismatch "
                            f"(ei_class={ei_class}, e_machine={e_machine}, expected class={exp_class}, machine={exp_machine})"
                        )
                        hard_fail = True
                        continue

                min_align = min(load_aligns)
                is_64bit_abi = abi in ("arm64-v8a", "x86_64")
                aligned_16k = all(a >= PAGE_16KB and a % PAGE_16KB == 0 for a in load_aligns)
                if is_64bit_abi and not aligned_16k:
                    tag = "FAIL" if strict_16kb else "WARN"
                    if strict_16kb:
                        hard_fail = True
                    else:
                        warnings += 1
                    print(
                        f"    [{tag}] lib/{abi}/{so_name}: {info.file_size} B, "
                        f"PT_LOAD min p_align={format_align(min_align)} (< 16 KB Android 15+ target)"
                    )
                else:
                    print(
                        f"    [PASS] lib/{abi}/{so_name}: {info.file_size} B, "
                        f"PT_LOAD min p_align={format_align(min_align)}"
                    )

    return not hard_fail, warnings


def audit_i18n_sources(repo_root: pathlib.Path) -> Tuple[bool, int]:
    targets = [
        repo_root / "app" / "src" / "main" / "java" / "org" / "telegram" / "wgplus" / "module" / "WgStrings.java",
        repo_root / "desktop-win" / "frontend" / "dist" / "i18n.js",
    ]
    hard_fail = False
    warnings = 0
    print("\n=== Auditing Arabic Localization Sources ===")
    for path in targets:
        if not path.is_file():
            print(f"  [WARN] Localization source missing: {path}")
            warnings += 1
            continue
        text = path.read_text(encoding="utf-8")
        emdash_cnt = text.count("\u2014")
        bad_tanween_cnt = text.count("\u0627\u064b")
        bad_telegram_cnt = text.count("تلغرام") + text.count("تليجرام")
        if emdash_cnt > 0 or bad_tanween_cnt > 0 or bad_telegram_cnt > 0:
            print(
                f"  [FAIL] {path.relative_to(repo_root)}: emdash={emdash_cnt}, "
                f"bad_tanween={bad_tanween_cnt}, bad_telegram={bad_telegram_cnt}"
            )
            hard_fail = True
        else:
            print(f"  [PASS] {path.relative_to(repo_root)}: 0 em-dashes, 0 bad tanween, 0 spelling violations")
    return not hard_fail, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Static APK, ELF ABI, and 16 KB alignment auditor.")
    parser.add_argument("apks", nargs="+", help="APK path(s) or glob pattern(s) to inspect")
    parser.add_argument(
        "--expect-abis",
        default="",
        help="Comma-separated expected ABIs (e.g. arm64-v8a,armeabi-v7a or x86_64)",
    )
    parser.add_argument(
        "--strict-16kb",
        action="store_true",
        help="Fail instead of warning when any 64-bit .so has < 16 KB PT_LOAD alignment",
    )
    parser.add_argument(
        "--skip-i18n",
        action="store_true",
        help="Skip repository Arabic string lint check",
    )
    args = parser.parse_args()

    resolved_apks: List[pathlib.Path] = []
    for item in args.apks:
        matched = sorted(glob.glob(item))
        if matched:
            resolved_apks.extend(pathlib.Path(m) for m in matched)
        else:
            resolved_apks.append(pathlib.Path(item))

    overall_ok = True
    total_warnings = 0

    for apk in resolved_apks:
        abis = infer_expected_abis(apk, args.expect_abis or None)
        ok, warns = audit_apk(apk, abis, args.strict_16kb)
        if not ok:
            overall_ok = False
        total_warnings += warns

    if not args.skip_i18n:
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        ok, warns = audit_i18n_sources(repo_root)
        if not ok:
            overall_ok = False
        total_warnings += warns

    print(f"\n=== Audit Summary: {'PASS' if overall_ok else 'FAIL'} (warnings={total_warnings}) ===")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
