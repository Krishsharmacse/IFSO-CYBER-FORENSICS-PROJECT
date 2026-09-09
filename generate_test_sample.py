"""
Generate a fake binary test file that contains all the string signatures
from the BlackEnergy_BE_2 YARA rule, so the rule triggers on it.

The file starts with the MZ header (0x4D 0x5A) and is under 250 KB.
It embeds both ASCII and wide (UTF-16LE) strings as required by the rule.

Usage:
    python generate_test_sample.py

Output:
    test_blackenergy_sample.bin  — binary file that should match the YARA rule
"""

import struct, os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_blackenergy_sample.bin")


def wide(s: str) -> bytes:
    """Encode a string as UTF-16LE (YARA 'wide' encoding) with null terminator."""
    return s.encode("utf-16-le") + b"\x00\x00"

def main():
    buf = bytearray()

    # ── 1. MZ header at offset 0 ──
    buf += b"MZ"  # 0x4D 0x5A

    # Pad with some realistic-looking PE stub bytes
    buf += b"\x90" * 58  # NOP sled to offset 0x3C
    pe_header_offset = 64
    buf += struct.pack("<I", pe_header_offset)  # e_lfanew at offset 0x3C

    # Minimal PE signature at the declared offset
    buf += b"PE\x00\x00"  # PE signature
    # Minimal COFF header (20 bytes)
    buf += struct.pack("<HHIIIHH",
        0x014C,  # Machine: i386
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        0,       # SizeOfOptionalHeader
        0x0102,  # Characteristics
    )

    # Pad to keep things tidy
    buf += b"\x00" * 128

    # ── 2. Embed the required ASCII strings ──
    # $s0 — ASCII fullword
    buf += b"\x00"
    buf += b"<description> Windows system utility service  </description>"
    buf += b"\x00"

    # $s3 — ASCII fullword
    buf += b"\x00"
    buf += b"WinHelpW"
    buf += b"\x00"

    # $s4 — ASCII fullword
    buf += b"\x00"
    buf += b"ReadProcessMemory"
    buf += b"\x00"

    # ── 3. Embed the required wide (UTF-16LE) strings ──
    # $s1 — wide fullword
    buf += b"\x00\x00"
    buf += wide("WindowsSysUtility - Unicode")

    # $s2 — wide fullword
    buf += b"\x00\x00"
    buf += wide("msiexec.exe")

    # Pad to a reasonable size (well under 250 KB)
    buf += b"\x00" * (4096 - len(buf))

    # ── Write output ──
    with open(OUTPUT, "wb") as f:
        f.write(buf)

    size = os.path.getsize(OUTPUT)
    print(f"[+] Test sample written to: {OUTPUT}")
    print(f"[+] File size: {size} bytes ({size/1024:.1f} KB)")
    print(f"[+] Starts with MZ header: {buf[0:2] == b'MZ'}")
    print(f"[+] Under 250 KB: {size < 250*1024}")
    print()
    print("Run YARA against it with:")
    print(f'    yara BlackEnergy.yar test_blackenergy_sample.bin')

if __name__ == "__main__":
    main()
