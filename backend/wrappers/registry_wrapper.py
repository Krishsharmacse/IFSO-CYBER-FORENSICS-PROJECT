"""
Registry Password Cracking Wrapper
Uses: impacket-secretsdump — extracts NTLM hashes from offline SAM+SYSTEM hives
Uses: john (John the Ripper) — cracks the extracted hashes

Cross-platform: works on Windows and Linux/macOS.
"""

import os
import tempfile
from wrappers.platform_utils import run, JOHN_BIN, SECRETSDUMP_BIN, IS_WINDOWS


def crack_registry(sam_path: str, system_path: str):
    if not os.path.exists(sam_path):
        return {"error": f"SAM hive not found: {sam_path}"}
    if not os.path.exists(system_path):
        return {"error": f"SYSTEM hive not found: {system_path}"}

    if not os.path.exists(SECRETSDUMP_BIN):
        return {
            "error": (
                "impacket-secretsdump is not installed in the virtual environment.\n"
                "Fix: pip install impacket"
            )
        }

    try:
        # 1. Extract hashes with impacket-secretsdump
        # On Windows the binary may be a .exe; on Linux it's a console script
        dump_cmd = [SECRETSDUMP_BIN, "-sam", sam_path, "-system", system_path, "LOCAL"]
        dump_proc = run(dump_cmd, timeout=60)

        dump_output = dump_proc.stdout
        if "Traceback" in dump_output or dump_proc.returncode != 0:
            return {
                "error"  : "Failed to extract hashes from registry hives.",
                "details": dump_output + "\n" + dump_proc.stderr
            }

        # 2. Parse NTLM hashes for John
        EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
        EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
        hashes = []
        for line in dump_output.split("\n"):
            if ":" in line and len(line.split(":")) >= 4:
                parts    = line.split(":")
                ntlm_hash = parts[3]
                if ntlm_hash and ntlm_hash not in ("empty", EMPTY_NT):
                    hashes.append(line)

        if not hashes:
            return {
                "status" : "Success",
                "message": "No crackable hashes found in the provided registry hives.",
                "raw_dump": dump_output.split("\n")
            }

        # 3. Write hashes to temp file
        fd, temp_hash_path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as tmp:
                tmp.write("\n".join(hashes))

            if not JOHN_BIN:
                return {
                    "status"          : "Partial Success",
                    "extracted_hashes": hashes,
                    "raw_dump"        : dump_output.split("\n"),
                    "warning"         : (
                        "John the Ripper is not installed — hashes extracted but not cracked.\n"
                        "Linux: sudo apt install john\n"
                        "Windows: https://www.openwall.com/john/"
                    )
                }

            # 4. Run John the Ripper with NT format
            john_proc = run([JOHN_BIN, "--format=NT", temp_hash_path], timeout=120)
            show_proc = run([JOHN_BIN, "--show", "--format=NT", temp_hash_path], timeout=30)

        finally:
            try:
                os.remove(temp_hash_path)
            except Exception:
                pass

        return {
            "status"          : "Success",
            "extracted_hashes": hashes,
            "john_crack_log"  : john_proc.stdout.strip().split("\n"),
            "john_results"    : show_proc.stdout.strip().split("\n"),
            "raw_dump"        : dump_output.split("\n")
        }

    except Exception as e:
        return {"error": str(e)}
