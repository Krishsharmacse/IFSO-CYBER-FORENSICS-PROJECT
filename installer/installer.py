"""
=============================================================================
  IFSO Cyber Forensics Platform — Windows Installer
  Console-mode installer (no GUI dependencies).
  Compile to EXE:  uv run pyinstaller --onefile --console --name IFSO_Setup installer.py
=============================================================================
"""

import os
import sys
import shutil
import ctypes
import zipfile
import urllib.request
import subprocess
import tempfile
import winreg
import time
from pathlib import Path

# ── ANSI colours (work in Windows 10+ conhost & Windows Terminal) ───────────
def _enable_ansi():
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
    except Exception:
        pass

_enable_ansi()

R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + R

# ── Paths ────────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    _HERE = Path(sys.executable).parent
else:
    _HERE = Path(__file__).parent

PROJECT_ROOT = _HERE.parent
PLUGINS_DIR  = PROJECT_ROOT / "plugins"
BACKEND_DIR  = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# ── Tool URLs ────────────────────────────────────────────────────────────────
JAVA_URL      = "https://aka.ms/download-jdk/microsoft-jdk-21.0.7-windows-x64.zip"
GHIDRA_VER    = "11.3.2"
GHIDRA_DATE   = "20250415"
GHIDRA_URL    = (f"https://github.com/NationalSecurityAgency/ghidra/releases/download/"
                 f"Ghidra_{GHIDRA_VER}_build/ghidra_{GHIDRA_VER}_{GHIDRA_DATE}.zip")
EXIFTOOL_URL  = "https://github.com/exiftool/exiftool/releases/download/13.10/exiftool-13.10_64.zip"
STEGHIDE_URL  = "https://downloads.sourceforge.net/project/steghide/steghide/0.5.1/steghide-0.5.1-win32.zip"
JOHN_URL      = "https://github.com/openwall/john/releases/download/1.9.0-Jumbo-1/john-1.9.0-jumbo-1-win64.zip"
TSK_URL       = "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.12.1/sleuthkit-4.12.1-win32.zip"
UV_URL        = "https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip"
NODE_URL      = "https://nodejs.org/dist/v22.12.0/node-v22.12.0-x64.msi"
WIRESHARK_URL = "https://2.na.dl.wireshark.org/win64/Wireshark-4.4.3-x64.exe"

# ── Helpers ──────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        " ".join(f'"{a}"' for a in sys.argv), None, 1
    )
    sys.exit(0)

def add_to_path(directory: str) -> bool:
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            0, winreg.KEY_ALL_ACCESS
        )
        current, _ = winreg.QueryValueEx(key, "Path")
        if directory.lower() not in current.lower():
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, current + ";" + directory)
        winreg.CloseKey(key)
        HWND_BROADCAST = 0xFFFF
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, 0x001A, 0, "Environment", 0x0002, 5000, None
        )
        return True
    except Exception:
        return False

def download_file(url: str, dest: Path, label: str = "") -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        total = int(resp.getheader("Content-Length", 0) or 0)
        chunk = 1 << 16
        done  = 0
        bar_w = 40
        with open(dest, "wb") as fh:
            while True:
                buf = resp.read(chunk)
                if not buf:
                    break
                fh.write(buf)
                done += len(buf)
                if total:
                    pct  = done * 100 // total
                    fill = done * bar_w // total
                    mb   = done / (1024 * 1024)
                    tmb  = total / (1024 * 1024)
                    bar  = GREEN + "#" * fill + DIM + "-" * (bar_w - fill) + R
                    sys.stdout.write(
                        f"\r    [{bar}] {pct:3d}%  {mb:.1f}/{tmb:.1f} MB  "
                    )
                    sys.stdout.flush()
    sys.stdout.write("\n")
    return dest

# ── Print helpers ─────────────────────────────────────────────────────────────
STEPS_TOTAL = 11

def header():
    w = 66
    print()
    print(c("=" * w, CYAN, B))
    print(c(f"  IFSO Cyber Forensics Platform — Windows Installer".center(w), CYAN, B))
    print(c("=" * w, CYAN, B))
    print(c(f"  Project root : {PROJECT_ROOT}", DIM))
    print(c(f"  Plugins dir  : {PLUGINS_DIR}", DIM))
    admin_txt = c("  [Administrator]", GREEN, B) if is_admin() else c("  [Not Admin — PATH/registry changes limited]", YELLOW)
    print(admin_txt)
    print(c("=" * w, CYAN, B))
    print()

def step_header(n: int, title: str, desc: str = ""):
    print()
    pct = f"[{n}/{STEPS_TOTAL}]"
    print(c(f" {pct} ", BLUE, B) + c(title, WHITE, B) + (c(f"  {desc}", DIM) if desc else ""))
    print(c("  " + "-" * 60, DIM))

def ok(msg: str):
    print(c("  [OK]   ", GREEN, B) + c(msg, GREEN))

def warn(msg: str):
    print(c("  [WARN] ", YELLOW, B) + c(msg, YELLOW))

def info(msg: str):
    print(c("  [..] ", CYAN) + msg)

def fail(msg: str):
    print(c("  [ERR] ", RED, B) + c(msg, RED))

# ──────────────────────────────────────────────────────────────────────────────
#   Installation steps
# ──────────────────────────────────────────────────────────────────────────────

_tmp = Path(tempfile.mkdtemp(prefix="cyberx_setup_"))
_errors = []

def run_step(name, fn):
    try:
        fn()
    except Exception as e:
        fail(f"{name} failed: {e}")
        _errors.append((name, str(e)))


# Step 1 ── uv ─────────────────────────────────────────────────────────────────
def install_uv():
    step_header(1, "uv  (Python package manager)", "https://github.com/astral-sh/uv")
    if shutil.which("uv"):
        ok("uv already on PATH, skipping.")
        return
    info("Downloading uv ...")
    tmp = _tmp / "uv.zip"
    download_file(UV_URL, tmp, "uv")
    with zipfile.ZipFile(tmp) as z:
        z.extractall(_tmp / "uv_ex")
    uv_dir = PROJECT_ROOT / ".tools" / "uv"
    uv_dir.mkdir(parents=True, exist_ok=True)
    for f in (_tmp / "uv_ex").rglob("uv.exe"):
        shutil.copy2(f, uv_dir / "uv.exe")
        break
    if add_to_path(str(uv_dir)):
        ok(f"uv installed → {uv_dir}")
    else:
        warn(f"uv installed but PATH update failed (not admin?). Add manually: {uv_dir}")


# Step 2 ── Node.js ────────────────────────────────────────────────────────────
def install_node():
    step_header(2, "Node.js", "Required for the React frontend")
    if shutil.which("node"):
        ver = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        ok(f"Node.js already installed: {ver}")
        return
    info("Downloading Node.js v22 MSI ...")
    msi = _tmp / "node.msi"
    download_file(NODE_URL, msi, "node")
    info("Running installer (silent, may take ~30 s) ...")
    result = subprocess.run(["msiexec", "/i", str(msi), "/qn", "/norestart"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"msiexec failed: {result.stderr[:200]}")
    ok("Node.js installed.")


# Step 3 ── Java 21 ────────────────────────────────────────────────────────────
def install_java():
    step_header(3, "Java 21 JDK", "Required by Ghidra")
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home and (Path(java_home) / "bin" / "java.exe").exists():
        ok(f"Java found at JAVA_HOME={java_home}")
        return
    if shutil.which("java"):
        v = subprocess.run(["java", "-version"], capture_output=True, text=True)
        ok(f"Java found on PATH: {v.stderr.strip().splitlines()[0]}")
        return
    info("Downloading Microsoft OpenJDK 21 (≈180 MB) ...")
    tmp = _tmp / "java21.zip"
    download_file(JAVA_URL, tmp, "java21")
    java_dir = PROJECT_ROOT / ".tools" / "java21"
    java_dir.mkdir(parents=True, exist_ok=True)
    info("Extracting JDK ...")
    with zipfile.ZipFile(tmp) as z:
        z.extractall(java_dir)
    jdk_root = next(java_dir.glob("jdk-*"), java_dir)
    bin_dir  = jdk_root / "bin"
    if not bin_dir.exists():
        bin_dir = java_dir / "bin"
    add_to_path(str(bin_dir))
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "JAVA_HOME", 0, winreg.REG_SZ, str(jdk_root))
        winreg.CloseKey(key)
    except Exception as e:
        warn(f"Could not set JAVA_HOME in registry: {e}")
    ok(f"Java 21 installed → {jdk_root}")


# Step 4 ── Wireshark / tshark ─────────────────────────────────────────────────
def install_wireshark():
    step_header(4, "Wireshark / tshark", "Network packet capture analysis")
    already = shutil.which("tshark") or (
        Path(r"C:\Program Files\Wireshark\tshark.exe").exists() and
        r"C:\Program Files\Wireshark\tshark.exe"
    )
    if already:
        ok(f"tshark already installed: {already}")
        return
    info("Downloading Wireshark (≈90 MB) ...")
    exe = _tmp / "wireshark.exe"
    download_file(WIRESHARK_URL, exe, "wireshark")
    info("Running Wireshark NSIS installer (/S = silent) ...")
    warn("UAC prompt may appear — please accept it.")
    subprocess.run([str(exe), "/S"], check=False)
    add_to_path(r"C:\Program Files\Wireshark")
    ok("Wireshark installed (if UAC was accepted).")


# Step 5 ── ExifTool ───────────────────────────────────────────────────────────
def install_exiftool():
    step_header(5, "ExifTool", "File metadata extraction")
    exif_dir = PLUGINS_DIR / "exiftool"
    dest_exe = exif_dir / "exiftool.exe"
    if dest_exe.exists():
        ok(f"ExifTool already at {dest_exe}")
        return
    if shutil.which("exiftool"):
        ok("ExifTool already on PATH")
        return
    info("Downloading ExifTool ...")
    tmp = _tmp / "exiftool.zip"
    download_file(EXIFTOOL_URL, tmp, "exiftool")
    exif_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp) as z:
        z.extractall(exif_dir)
    # Rename exiftool(-k).exe → exiftool.exe
    for f in exif_dir.rglob("exiftool*.exe"):
        if f.name != "exiftool.exe":
            f.rename(dest_exe)
        break
    add_to_path(str(exif_dir))
    ok(f"ExifTool installed → {dest_exe}")


# Step 6 ── Steghide ───────────────────────────────────────────────────────────
def install_steghide():
    step_header(6, "Steghide", "Steganography detection & extraction")
    sg_dir  = PLUGINS_DIR / "steghide"
    sg_exe  = sg_dir / "steghide.exe"
    if sg_exe.exists():
        ok(f"Steghide already at {sg_exe}")
        return
    if shutil.which("steghide"):
        ok("Steghide already on PATH")
        return
    info("Downloading Steghide ...")
    tmp = _tmp / "steghide.zip"
    download_file(STEGHIDE_URL, tmp, "steghide")
    sg_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp) as z:
        z.extractall(sg_dir)
    for f in sg_dir.rglob("steghide.exe"):
        if f != sg_exe:
            shutil.copy2(f, sg_exe)
        break
    add_to_path(str(sg_dir))
    ok(f"Steghide installed → {sg_exe}")


# Step 7 ── Ghidra ─────────────────────────────────────────────────────────────
def install_ghidra():
    step_header(7, f"Ghidra {GHIDRA_VER}", "Reverse engineering & binary analysis")
    for ex in PLUGINS_DIR.glob("ghidra_*/support/analyzeHeadless.bat"):
        ok(f"Ghidra already at {ex.parent.parent}")
        return
    info(f"Downloading Ghidra {GHIDRA_VER} (≈450 MB) — please wait ...")
    tmp = _tmp / "ghidra.zip"
    download_file(GHIDRA_URL, tmp, "ghidra")
    info("Extracting Ghidra (this may take a minute) ...")
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp) as z:
        z.extractall(PLUGINS_DIR)
    for ex in PLUGINS_DIR.glob("ghidra_*/support/analyzeHeadless.bat"):
        ok(f"Ghidra installed → {ex.parent.parent}")
        return
    warn("Ghidra extracted but analyzeHeadless.bat not found — check plugins/ folder.")


# Step 8 ── John the Ripper ────────────────────────────────────────────────────
def install_john():
    step_header(8, "John the Ripper", "Password & hash cracking")
    john_dir = PLUGINS_DIR / "john"
    for ex in john_dir.rglob("john.exe"):
        ok(f"John already at {ex}")
        add_to_path(str(ex.parent))
        return
    if shutil.which("john"):
        ok("John already on PATH")
        return
    info("Downloading John the Ripper (≈50 MB) ...")
    tmp = _tmp / "john.zip"
    download_file(JOHN_URL, tmp, "john")
    john_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp) as z:
        z.extractall(john_dir)
    for ex in john_dir.rglob("john.exe"):
        add_to_path(str(ex.parent))
        ok(f"John installed → {ex}")
        return
    warn("John extracted but john.exe not found — check plugins/john/")


# Step 9 ── SleuthKit ──────────────────────────────────────────────────────────
def install_sleuthkit():
    step_header(9, "The Sleuth Kit (TSK)", "Disk image & filesystem forensics")
    tsk_dir = PLUGINS_DIR / "sleuthkit"
    for ex in tsk_dir.rglob("mmls.exe"):
        ok(f"SleuthKit already at {ex.parent}")
        add_to_path(str(ex.parent))
        return
    if shutil.which("mmls"):
        ok("SleuthKit already on PATH")
        return
    info("Downloading SleuthKit ...")
    tmp = _tmp / "tsk.zip"
    try:
        download_file(TSK_URL, tmp, "sleuthkit")
        tsk_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp) as z:
            z.extractall(tsk_dir)
        for ex in tsk_dir.rglob("mmls.exe"):
            add_to_path(str(ex.parent))
            ok(f"SleuthKit installed → {ex.parent}")
            return
    except Exception as e:
        warn(f"Download failed ({e}). Install manually: https://www.sleuthkit.org/sleuthkit/download.php")


# Step 10 ── Python packages ───────────────────────────────────────────────────
def install_python_packages():
    step_header(10, "Python backend packages", "Via uv pip install")
    uv_cmd = shutil.which("uv") or str(PROJECT_ROOT / ".tools" / "uv" / "uv.exe")
    pkgs = [
        "fastapi", "uvicorn", "sqlalchemy", "python-dotenv",
        "yara-python", "joblib", "pandas", "scikit-learn", "numpy",
        "requests", "paramiko", "pyzipper", "pikepdf",
        "eml-parser", "python-evtx",
        "impacket", "python-whois",
        "androguard",
        "pefile", "pyelftools",
    ]
    info("Running: uv pip install <packages> ...")
    result = subprocess.run(
        [uv_cmd, "pip", "install"] + pkgs,
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    if result.returncode != 0:
        warn(f"Some packages may have failed:\n{result.stderr[:600]}")
    else:
        ok("All Python packages installed.")

    # Also install frontend npm
    step_header(10, "Frontend npm packages", "npm install")
    npm_cmd = shutil.which("npm") or "npm"
    if FRONTEND_DIR.exists():
        info("Running npm install in frontend/ ...")
        r = subprocess.run([npm_cmd, "install"], capture_output=True, text=True, cwd=str(FRONTEND_DIR))
        if r.returncode != 0:
            warn(f"npm install had issues: {r.stderr[:300]}")
        else:
            ok("Frontend packages installed.")
    else:
        warn(f"frontend/ not found, skipping npm install.")


# Step 11 ── Finalise ──────────────────────────────────────────────────────────
def finalise():
    step_header(11, "Finalise", ".env, Defender exclusion, verification")

    # .env
    env_f = BACKEND_DIR / ".env"
    env_e = BACKEND_DIR / ".env.example"
    if not env_f.exists():
        if env_e.exists():
            shutil.copy2(env_e, env_f)
            ok(f"Created {env_f} from .env.example")
        else:
            env_f.write_text("# Add your API keys here\n")
            ok(f"Created empty {env_f}")
    else:
        ok(f"{env_f} already exists")

    # Defender exclusion
    if is_admin():
        try:
            subprocess.run(
                ["powershell", "-Command",
                 f"Add-MpPreference -ExclusionPath '{PROJECT_ROOT}' -ErrorAction SilentlyContinue"],
                capture_output=True, timeout=15
            )
            ok("Windows Defender exclusion added for project root.")
        except Exception as e:
            warn(f"Defender exclusion failed: {e}")
    else:
        warn("Not admin — skipping Windows Defender exclusion.")

    # Verification
    print()
    print(c("  ── Tool Verification ──", CYAN, B))
    checks = {
        "uv":        bool(shutil.which("uv") or (PROJECT_ROOT / ".tools" / "uv" / "uv.exe").exists()),
        "node":      shutil.which("node") is not None,
        "java":      bool(shutil.which("java") or (PROJECT_ROOT / ".tools" / "java21").exists()),
        "tshark":    bool(shutil.which("tshark") or Path(r"C:\Program Files\Wireshark\tshark.exe").exists()),
        "exiftool":  bool((PLUGINS_DIR / "exiftool" / "exiftool.exe").exists() or shutil.which("exiftool")),
        "steghide":  bool((PLUGINS_DIR / "steghide" / "steghide.exe").exists() or shutil.which("steghide")),
        "ghidra":    any(PLUGINS_DIR.glob("ghidra_*/support/analyzeHeadless.bat")),
        "john":      bool(any(PLUGINS_DIR.glob("john/**/john.exe")) or shutil.which("john")),
        "sleuthkit": bool(any((PLUGINS_DIR / "sleuthkit").rglob("mmls.exe")) if (PLUGINS_DIR / "sleuthkit").exists() else shutil.which("mmls")),
    }
    for tool, ok_val in checks.items():
        sym = c("[OK]     ", GREEN, B) if ok_val else c("[MISSING]", YELLOW, B)
        print(f"    {sym} {tool}")


# ── Summary banner ────────────────────────────────────────────────────────────
def summary():
    print()
    w = 66
    if _errors:
        print(c("=" * w, YELLOW, B))
        print(c(f"  Completed with {len(_errors)} warning(s):".center(w), YELLOW, B))
        for name, err in _errors:
            print(c(f"    • {name}: {err[:80]}", YELLOW))
        print(c("=" * w, YELLOW, B))
    else:
        print(c("=" * w, GREEN, B))
        print(c("  All tools installed successfully!".center(w), GREEN, B))
        print(c("=" * w, GREEN, B))

    print()
    print(c("  To start the platform:", WHITE, B))
    print(c("    Double-click  run_windows.bat", CYAN))
    print(c("  OR manually:", DIM))
    print(c(r"    Backend  : cd backend && uv run .\main.py", DIM))
    print(c(r"    Frontend : cd frontend && npm run dev", DIM))
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    header()

    if not is_admin():
        print(c("  ⚠  Not running as Administrator.", YELLOW, B))
        print(c("     Some operations (PATH changes, Wireshark) may require admin.", YELLOW))
        ans = input(c("\n  Re-launch with Administrator rights? [Y/n] ", WHITE, B)).strip().lower()
        if ans in ("", "y"):
            elevate()
        print()

    print(c("  Press ENTER to start installation, or Ctrl+C to cancel.", DIM))
    input()

    steps = [
        install_uv,
        install_node,
        install_java,
        install_wireshark,
        install_exiftool,
        install_steghide,
        install_ghidra,
        install_john,
        install_sleuthkit,
        install_python_packages,
        finalise,
    ]
    for fn in steps:
        run_step(fn.__name__, fn)

    summary()

    try:
        shutil.rmtree(_tmp, ignore_errors=True)
    except Exception:
        pass

    input(c("\n  Press ENTER to exit ...", DIM))


if __name__ == "__main__":
    main()
