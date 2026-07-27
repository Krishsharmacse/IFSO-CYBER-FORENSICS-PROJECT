import os
import sys
import zipfile
import subprocess
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = BACKEND_DIR.parent
PLUGINS_DIR = PROJECT_ROOT / "plugins"

def download_file(url, dest_path):
    print(f"Downloading {url} to {dest_path}...")
    cmd = [
        "powershell", "-Command",
        f"Invoke-WebRequest -Uri '{url}' -OutFile '{dest_path}' -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'"
    ]
    subprocess.run(cmd, check=True)

def setup_exiftool():
    exiftool_dir = PLUGINS_DIR / "exiftool"
    exiftool_exe = exiftool_dir / "exiftool.exe"
    
    if exiftool_exe.exists():
        print("[OK] ExifTool is already installed.")
        return

    os.makedirs(exiftool_dir, exist_ok=True)
    temp_zip = exiftool_dir / "exiftool.zip"
    url = "https://downloads.sourceforge.net/project/exiftool/exiftool-13.10_64.zip"

    try:
        download_file(url, temp_zip)
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            zip_ref.extractall(exiftool_dir)
        
        extracted_exes = list(exiftool_dir.glob("exiftool*.exe"))
        if not extracted_exes:
            for f in exiftool_dir.glob("*.exe"):
                if "exiftool" in f.name:
                    extracted_exes.append(f)
        
        if extracted_exes:
            extracted_exe = extracted_exes[0]
            if extracted_exe.name != "exiftool.exe":
                os.rename(extracted_exe, exiftool_exe)
            print("[OK] ExifTool installed successfully.")
        else:
            for root, dirs, files in os.walk(exiftool_dir):
                for file in files:
                    if file.startswith("exiftool") and file.endswith(".exe"):
                        os.rename(Path(root) / file, exiftool_exe)
                        print("[OK] ExifTool installed successfully from subdirectory.")
                        break
        if temp_zip.exists():
            os.remove(temp_zip)
    except Exception as e:
        print("\n--- ExifTool Manual Installation Needed ---")
        print("1. Go to: https://exiftool.org/ or https://sourceforge.net/projects/exiftool/files/")
        print("2. Download the Windows version zip (e.g. exiftool-13.10_64.zip)")
        print(f"3. Extract and rename the executable to 'exiftool.exe'")
        print(f"4. Move 'exiftool.exe' into this directory: {exiftool_dir}\n")

def setup_steghide():
    steghide_dir = PLUGINS_DIR / "steghide"
    steghide_exe = steghide_dir / "steghide.exe"
    
    if steghide_exe.exists():
        print("[OK] Steghide is already installed.")
        return

    os.makedirs(steghide_dir, exist_ok=True)
    temp_zip = steghide_dir / "steghide.zip"
    url = "https://downloads.sourceforge.net/project/steghide/steghide/0.5.1/steghide-0.5.1-win32.zip"

    try:
        download_file(url, temp_zip)
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            zip_ref.extractall(steghide_dir)
        
        for root, dirs, files in os.walk(steghide_dir):
            for file in files:
                if file.lower() == "steghide.exe":
                    p = Path(root) / file
                    if p != steghide_exe:
                        os.rename(p, steghide_exe)
                    print("[OK] Steghide installed successfully.")
                    break
        if temp_zip.exists():
            os.remove(temp_zip)
    except Exception as e:
        print("\n--- Steghide Manual Installation Needed ---")
        print("1. Go to: https://sourceforge.net/projects/steghide/files/steghide/0.5.1/")
        print("2. Download 'steghide-0.5.1-win32.zip'")
        print("3. Extract and look for 'steghide.exe'")
        print(f"4. Move 'steghide.exe' into this directory: {steghide_dir}\n")

if __name__ == "__main__":
    if sys.platform != "win32":
        print("This script is only intended for Windows setups.")
        sys.exit(0)
    setup_exiftool()
    setup_steghide()
