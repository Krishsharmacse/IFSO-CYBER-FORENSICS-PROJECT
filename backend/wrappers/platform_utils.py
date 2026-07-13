"""
CyberX Platform Utilities
Centralised cross-platform helper for resolving binary paths, OS detection,
and common path operations — supports Windows + Linux/macOS.
"""

import os
import sys
import shutil
import platform
import subprocess
import tempfile
from pathlib import Path

# ── OS Detection ──────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

# Root of the repository (two levels above this file: backend/wrappers/platform_utils.py)
_WRAPPER_DIR  = Path(__file__).parent.resolve()
_BACKEND_DIR  = _WRAPPER_DIR.parent
_PROJECT_ROOT = _BACKEND_DIR.parent
_PLUGINS_DIR  = _PROJECT_ROOT / "plugins"
_VENV_DIR     = _PROJECT_ROOT / ".venv"


# ── Temp directory helper ─────────────────────────────────────────────────────
def get_temp_dir(prefix: str = "cyberx_") -> Path:
    """Return a freshly created temporary directory that works on all OS."""
    return Path(tempfile.mkdtemp(prefix=prefix))


def safe_temp_file(suffix: str = ".txt", mode: str = "w") -> str:
    """Return path to a temp file safe to write on Windows (delete=False)."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


# ── Wordlist path ─────────────────────────────────────────────────────────────
WORDLIST_PATH = _BACKEND_DIR / "wordlists" / "top10000.txt"


# ── Generic binary resolver ───────────────────────────────────────────────────
def find_binary(name: str, windows_names: list = None, extra_paths: list = None) -> str | None:
    """
    Find a system binary across platforms.
    - name          : canonical unix binary name (e.g. 'john')
    - windows_names : alternative names on Windows (e.g. ['john.exe', 'john'])
    - extra_paths   : additional directories to search
    Returns the full resolved path as a string, or None.
    """
    candidates = []
    if IS_WINDOWS and windows_names:
        candidates.extend(windows_names)
    else:
        candidates.append(name)

    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found

    # Search extra paths
    search_dirs = extra_paths or []
    # Always add the venv Scripts / bin dir
    venv_bin = _VENV_DIR / ("Scripts" if IS_WINDOWS else "bin")
    search_dirs.append(str(venv_bin))

    for d in search_dirs:
        for cand in candidates:
            full = Path(d) / cand
            if full.exists():
                return str(full)

    return None


# ── John the Ripper ───────────────────────────────────────────────────────────
def get_john_binary() -> str | None:
    if IS_WINDOWS:
        return find_binary("john", ["john.exe", "john"],
                           extra_paths=[r"C:\Program Files\John the Ripper",
                                        r"C:\John\run"])
    # Linux: common locations
    for path in ["/usr/sbin/john", "/usr/bin/john", "/usr/local/bin/john"]:
        if os.path.exists(path):
            return path
    return find_binary("john")


JOHN_BIN = get_john_binary()

# John built-in wordlist
def get_john_wordlist() -> str | None:
    candidates = [
        "/usr/share/john/password.lst",        # Debian/Ubuntu
        "/usr/local/share/john/password.lst",  # Homebrew macOS
        r"C:\Program Files\John the Ripper\run\password.lst",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

JOHN_WORDLIST = get_john_wordlist()


def john_available() -> bool:
    if not JOHN_BIN:
        return False
    try:
        r = subprocess.run([JOHN_BIN], capture_output=True, timeout=5)
        banner = r.stdout + r.stderr
        return b"John the Ripper" in banner
    except Exception:
        return False


# ── ExifTool ──────────────────────────────────────────────────────────────────
def get_exiftool_binary() -> str:
    """Return exiftool command name; on Windows tries exiftool.exe and the
    bundled Perl script via plugins/exiftool."""
    if IS_WINDOWS:
        found = find_binary("exiftool", ["exiftool.exe"],
                             extra_paths=[str(_PLUGINS_DIR / "exiftool")])
        return found or "exiftool"
    return find_binary("exiftool") or "exiftool"

EXIFTOOL_BIN = get_exiftool_binary()


# ── Steghide ──────────────────────────────────────────────────────────────────
def get_steghide_binary() -> str:
    if IS_WINDOWS:
        found = find_binary("steghide", ["steghide.exe"],
                             extra_paths=[str(_PLUGINS_DIR / "steghide")])
        return found or "steghide"
    return find_binary("steghide") or "steghide"

STEGHIDE_BIN = get_steghide_binary()


# ── tshark / Wireshark ────────────────────────────────────────────────────────
def get_tshark_binary() -> str:
    if IS_WINDOWS:
        found = find_binary("tshark", ["tshark.exe"],
                             extra_paths=[r"C:\Program Files\Wireshark"])
        return found or "tshark"
    return find_binary("tshark") or "tshark"

TSHARK_BIN = get_tshark_binary()


# ── Volatility 3 ─────────────────────────────────────────────────────────────
def get_volatility_binary() -> str:
    """vol / vol.py / vol3; on Windows may also be vol.exe."""
    if IS_WINDOWS:
        found = find_binary("vol", ["vol.exe", "vol3.exe", "volatility.exe"])
        if found:
            return found
        # Try running as python module
        return "vol"
    for name in ["vol", "vol3", "volatility3"]:
        found = find_binary(name)
        if found:
            return found
    return "vol"

VOLATILITY_BIN = get_volatility_binary()


# ── Sleuth Kit (mmls, fls, fsstat, mactime) ───────────────────────────────────
def get_sleuthkit_tool(tool: str) -> str:
    """Return the path to a Sleuth Kit tool, e.g. mmls, fls, fsstat, mactime."""
    if IS_WINDOWS:
        found = find_binary(tool, [f"{tool}.exe"],
                             extra_paths=[str(_PLUGINS_DIR / "sleuthkit" / "bin")])
        return found or tool
    return find_binary(tool) or tool


# ── Ghidra headless ──────────────────────────────────────────────────────────
def get_ghidra_headless() -> str:
    """Return path to analyzeHeadless (Linux) or analyzeHeadless.bat (Windows)."""
    # Search bundled plugin dir first
    ghidra_dirs = list(_PLUGINS_DIR.glob("ghidra_*")) + list(_PLUGINS_DIR.glob("ghidra"))
    for d in ghidra_dirs:
        if IS_WINDOWS:
            script = d / "support" / "analyzeHeadless.bat"
        else:
            script = d / "support" / "analyzeHeadless"
        if script.exists():
            return str(script)

    # Fall back to PATH
    if IS_WINDOWS:
        return find_binary("analyzeHeadless", ["analyzeHeadless.bat"]) or "analyzeHeadless.bat"
    return find_binary("analyzeHeadless") or "analyzeHeadless"

GHIDRA_HEADLESS = get_ghidra_headless()


# ── impacket secretsdump ──────────────────────────────────────────────────────
def get_secretsdump_binary() -> str:
    r"""
    Return the secretsdump command.
    - Linux/macOS venv: .venv/bin/impacket-secretsdump  (installed as console script)
    - Windows venv  :   .venv\Scripts\impacket-secretsdump.exe
    - Fallback      :   secretsdump.py somewhere on PATH
    """
    venv_bin = _VENV_DIR / ("Scripts" if IS_WINDOWS else "bin")
    candidates_win = [
        str(venv_bin / "impacket-secretsdump.exe"),
        str(venv_bin / "secretsdump.exe"),
    ]
    candidates_linux = [
        str(venv_bin / "impacket-secretsdump"),
        str(venv_bin / "secretsdump.py"),
        "/usr/bin/impacket-secretsdump",
        "/usr/local/bin/impacket-secretsdump",
    ]
    candidates = candidates_win if IS_WINDOWS else candidates_linux
    for c in candidates:
        if os.path.exists(c):
            return c
    # Fallback: let shutil.which try
    return find_binary("impacket-secretsdump",
                       ["impacket-secretsdump.exe"]) or "impacket-secretsdump"

SECRETSDUMP_BIN = get_secretsdump_binary()


# ── Body file temp path (autopsy timeline) ────────────────────────────────────
def get_body_file_path(image_path: str) -> str:
    """Return a safe temp path for the mactime body file (cross-platform)."""
    tmp = Path(tempfile.gettempdir())
    name = Path(image_path).stem + ".body"
    return str(tmp / name)


# ── Subprocess helper ─────────────────────────────────────────────────────────
def run(cmd: list, timeout: int = 120, **kwargs) -> subprocess.CompletedProcess:
    """
    subprocess.run wrapper that adds CREATE_NO_WINDOW on Windows
    so the terminal doesn't flash, and passes sensible defaults.
    """
    extra = {}
    if IS_WINDOWS:
        import ctypes
        CREATE_NO_WINDOW = 0x08000000
        extra["creationflags"] = CREATE_NO_WINDOW

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        **extra,
        **kwargs,
    )


# ── Diagnostics ───────────────────────────────────────────────────────────────
def get_platform_info() -> dict:
    """Return a diagnostic summary of all resolved tool paths."""
    return {
        "os"           : platform.system(),
        "os_version"   : platform.version(),
        "python"       : sys.version,
        "john"         : JOHN_BIN,
        "john_wordlist": JOHN_WORDLIST,
        "exiftool"     : EXIFTOOL_BIN,
        "steghide"     : STEGHIDE_BIN,
        "tshark"       : TSHARK_BIN,
        "volatility"   : VOLATILITY_BIN,
        "ghidra"       : GHIDRA_HEADLESS,
        "secretsdump"  : SECRETSDUMP_BIN,
        "wordlist"     : str(WORDLIST_PATH),
        "plugins_dir"  : str(_PLUGINS_DIR),
    }
