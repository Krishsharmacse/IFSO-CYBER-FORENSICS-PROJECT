import os
from wrappers.platform_utils import run, get_sleuthkit_tool, get_body_file_path, IS_WINDOWS

def run_sleuthkit(image_path: str, scan_type: str = "mmls"):
    """
    Uses Sleuth Kit to analyse a disk image.
    Supports mmls, fsstat, fls, timeline — cross-platform (Windows + Linux).
    """
    if not os.path.exists(image_path):
        return {"error": f"Disk image file not found: {image_path}"}

    results = {}

    try:
        if scan_type == "mmls":
            mmls = get_sleuthkit_tool("mmls")
            proc = run([mmls, image_path])
            if proc.returncode == 0:
                results['partitions'] = proc.stdout.strip().split('\n')
                results['status'] = 'Success'
            else:
                results['error'] = "Could not parse partitions (no volume system or mmls not installed)."
                results['details'] = proc.stderr

        elif scan_type == "fsstat":
            fsstat = get_sleuthkit_tool("fsstat")
            proc = run([fsstat, image_path])
            if proc.returncode == 0:
                results['file_system_info'] = proc.stdout.strip().split('\n')
                results['status'] = 'Success'
            else:
                results['error'] = "Could not parse file system details (fsstat failed)."
                results['details'] = proc.stderr

        elif scan_type == "fls":
            fls = get_sleuthkit_tool("fls")
            proc = run([fls, '-r', image_path])
            if proc.returncode == 0:
                output_lines = proc.stdout.strip().split('\n')
                results['files'] = output_lines[:1000]
                if len(output_lines) > 1000:
                    results['notice'] = f"Truncated output. Found {len(output_lines)} total files. Showing first 1000."
                results['status'] = 'Success'
            else:
                results['error'] = "Could not list files (fls failed). Provide partition offset if image has multiple partitions."
                results['details'] = proc.stderr

        elif scan_type == "timeline":
            fls = get_sleuthkit_tool("fls")
            mactime = get_sleuthkit_tool("mactime")
            body_proc = run([fls, '-r', '-m', '/', image_path])
            if body_proc.returncode == 0:
                # Use a temp path safe for both OS
                body_file_path = get_body_file_path(image_path)
                with open(body_file_path, "w", encoding="utf-8") as f:
                    f.write(body_proc.stdout)

                mac_proc = run([mactime, '-b', body_file_path])
                output_lines = mac_proc.stdout.strip().split('\n')
                results['timeline'] = output_lines[:2000]
                if len(output_lines) > 2000:
                    results['notice'] = f"Truncated timeline. Found {len(output_lines)} events. Showing first 2000."
                results['status'] = 'Success'

                try:
                    os.remove(body_file_path)
                except Exception:
                    pass
            else:
                results['error'] = "Could not generate timeline (fls failed to build body file)."
                results['details'] = body_proc.stderr

        else:
            results['error'] = f"Unknown scan type: {scan_type}"

    except FileNotFoundError as e:
        tool_name = str(e).split("'")[1] if "'" in str(e) else "Sleuth Kit tool"
        install_hint = (
            "Windows: Download SleuthKit from https://www.sleuthkit.org/sleuthkit/download.php and add bin/ to PATH"
            if IS_WINDOWS else
            "Linux: sudo apt install sleuthkit"
        )
        results['error'] = f"{tool_name} not found. {install_hint}"
    except Exception as e:
        results['error'] = f"Sleuth Kit Execution Failed: {str(e)}"

    return results

# Alias used by main.py
analyze_image = run_sleuthkit
