

import os
import re
import csv
import json
import time
import shutil
import hashlib
import tempfile
import logging
import platform
import subprocess
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Generator
from dataclasses import dataclass, field, asdict
from enum import Enum

from wrappers.platform_utils import run, get_sleuthkit_tool, get_body_file_path, IS_WINDOWS


class SIEMJSONFormatter(logging.Formatter):
    """Formats logs into structured JSON objects optimized for ELK/Splunk ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "audit_event"):
            log_entry["audit_event"] = record.audit_event
        if hasattr(record, "artifact_hash"):
            log_entry["artifact_hash"] = record.artifact_hash
        return json.dumps(log_entry)

logger = logging.getLogger("DFIR_Enterprise")
log_handler = logging.StreamHandler()
log_handler.setFormatter(SIEMJSONFormatter())
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)


class FileCategory(str, Enum):
    DOCUMENT = "Document"; IMAGE = "Image"; EXECUTABLE = "Executable"
    DATABASE = "Database"; CONFIG = "Configuration"; SYSTEM = "System"
    DELETED = "Deleted"; SUSPICIOUS = "Suspicious"; OTHER = "Other"

@dataclass
class FileEntry:
    name: str; path: str; inode: str; size: int; type: str
    is_deleted: bool = False
    category: FileCategory = FileCategory.OTHER
    extension: str = ""


class SleuthKitAnalyzer:
    """
    Enterprise-grade Sleuth Kit wrapper featuring Context Management,
    Memory Streaming, and Failure Checkpoint Recovery.
    """
    def __init__(self, image_path: str, output_dir: str, offset: Optional[int] = None):
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Target image missing: {image_path}")
            
        self.image_path = os.path.abspath(image_path)
        self.output_dir = os.path.abspath(output_dir)
        self.offset = offset
        self.temp_dir = tempfile.mkdtemp(prefix="dfir_ent_")
        self.checkpoint_file = os.path.join(self.output_dir, ".forensic_checkpoint")
        self.state = self._load_checkpoint()
        
        os.makedirs(self.output_dir, exist_ok=True)
        self._generate_audit_trail("ANALYZER_INITIALIZED", self.image_path)

    def __enter__(self):
        logger.info("Entering secure forensic analysis execution context.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensures complete resource liberation and records crashes to checkpoint."""
        if exc_type:
            logger.error(f"Execution context interrupted by exception: {exc_val}")
            self._save_checkpoint("FAILED", {"error": str(exc_val)})
        else:
            self._generate_audit_trail("ANALYZER_CONTEXT_CLEANUP", self.image_path)
            
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            
        return False

    def _generate_audit_trail(self, event_type: str, target: str):
        """Calculates running validation logs to protect the Chain of Custody."""
        try:
            target_hash = ""
            if os.path.isfile(target) and event_type == "ANALYZER_INITIALIZED":
                hash_func = hashlib.sha256()
                with open(target, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        hash_func.update(chunk)
                target_hash = hash_func.hexdigest()

            logger.info(
                f"Audit Event: {event_type} evaluated on target.",
                extra={"audit_event": event_type, "artifact_hash": target_hash}
            )
        except Exception as e:
            logger.error(f"Failed to generate secure audit log: {e}")

    def _load_checkpoint(self) -> Dict[str, Any]:
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    logger.info("Discovered existing forensic session state checkpoint. Resuming operational loop.")
                    return json.load(f)
            except Exception:
                logger.warning("Checkpoint metadata corrupted. Initializing vanilla session map.")
        return {"completed_stages": [], "status": "PENDING", "runtime_metrics": {}}

    def _save_checkpoint(self, stage_completed: str, metrics: Dict[str, Any] = None):
        if stage_completed not in self.state["completed_stages"]:
            self.state["completed_stages"].append(stage_completed)
        if metrics:
            self.state["runtime_metrics"].update(metrics)
        
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(self.state, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to commit operational state checkpoint: {e}")

    def stream_file_manifest(self, max_files: int = 500000) -> Generator[FileEntry, None, None]:
        """Streams system image output via Python Generators to guarantee a low memory profile."""
        if "FILE_MANIFEST_STREAM" in self.state["completed_stages"]:
            logger.info("Skipping Manifest Generation: Verified complete in state checkpoint.")
            return

        tool_path = shutil.which("fls") or get_sleuthkit_tool("fls")
        if not tool_path:
            raise RuntimeError("Missing Sleuth Kit 'fls' executable dependency.")

        cmd = [tool_path, '-r', '-l', '-z', 'UTC']
        if self.offset:
            cmd.extend(['-o', str(self.offset)])
        cmd.append(self.image_path)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        try:
            count = 0
            for line in process.stdout:
                if count >= max_files:
                    logger.warning(f"Engine reached hard manifest bounds adjustment cap: {max_files}")
                    break
                if not line.strip():
                    continue
                
                parts = line.split('\t')
                if len(parts) < 7:
                    continue
                
                type_inode = parts[0].split()
                entry_type = type_inode[0] if len(type_inode) > 0 else "unknown"
                inode = type_inode[1].rstrip(':') if len(type_inode) > 1 else ""
                
                path = parts[1].lstrip('/')
                name = os.path.basename(path)
                size_str = parts[6] if len(parts) > 6 else "0"
                size = int(size_str) if size_str.isdigit() else 0
                is_deleted = '*' in entry_type or '(deleted)' in line
                
                ext = os.path.splitext(name)[1].lower()
                category = FileCategory.DELETED if is_deleted else (FileCategory.SYSTEM if ext in ['.sys', '.dll'] else FileCategory.OTHER)

                count += 1
                yield FileEntry(name=name, path=path, inode=inode, size=size, type=entry_type, is_deleted=is_deleted, category=category, extension=ext)
                
            process.terminate()
            self._save_checkpoint("FILE_MANIFEST_STREAM", {"total_streamed_records": count})
            
        except Exception as e:
            process.kill()
            raise RuntimeError(f"Pipeline crashed during streaming conversion execution: {e}")

    def concurrent_artifact_extraction(self, files_to_extract: List[FileEntry], thread_timeout: float = 30.0) -> List[Dict[str, Any]]:
        """Executes thread pool data extractions backed by deterministic execution timeouts."""
        icat_path = shutil.which("icat") or get_sleuthkit_tool("icat")
        if not icat_path:
            logger.error("Sleuth Kit 'icat' tool missing. Aborting batch execution.")
            return []

        extract_dir = os.path.join(self.output_dir, "extracted_artifacts")
        os.makedirs(extract_dir, exist_ok=True)
        extracted_results = []

        def extract_single_inode(file_entry: FileEntry):
            out_file = os.path.join(extract_dir, f"{file_entry.inode}_{file_entry.name}")
            cmd = [icat_path]
            if self.offset:
                cmd.extend(['-o', str(self.offset)])
            cmd.extend([self.image_path, file_entry.inode])

            try:
                res = subprocess.run(cmd, capture_output=True, timeout=thread_timeout)
                if res.returncode == 0:
                    with open(out_file, 'wb') as f:
                        f.write(res.stdout)
                    return {"success": True, "file": out_file, "entry": asdict(file_entry)}
            except subprocess.TimeoutExpired:
                logger.warning(f"Extraction execution timed out processing Inode: {file_entry.inode}")
            return {"success": False, "inode": file_entry.inode}

        workers = min(32, (os.cpu_count() or 1) + 4)
        logger.info(f"Launching multi-threaded hardware asset deployment framework utilizing {workers} workers.")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(extract_single_inode, f): f for f in files_to_extract}
            for future in concurrent.futures.as_completed(futures):
                entry = futures[future]
                try:
                    result = future.result()
                    extracted_results.append(result)
                    if result.get("success"):
                        self._generate_audit_trail("ARTIFACT_EXTRACTION_SUCCESS", result["file"])
                except Exception as e:
                    logger.error(f"Asynchronous worker pool processing failure: {e}")
                    
        return extracted_results


def run_enterprise_pipeline(image: str, output: str, offset: Optional[int] = None) -> Dict[str, Any]:
    """Execution wrapper leveraging the Context Manager lifecycle interface."""
    results = {"status": "Started", "suspicious_files_extracted": 0, "extracted_data": []}
    
    with SleuthKitAnalyzer(image_path=image, output_dir=output, offset=offset) as analyzer:
        
        logger.info("Initializing Generator-driven disk analysis processing stream.")
        suspicious_targets = []
        
        for file_entry in analyzer.stream_file_manifest():
            if file_entry.size > 50 * 1024 * 1024 and file_entry.extension in ['.exe', '.sh', '.bat']:
                file_entry.category = FileCategory.SUSPICIOUS
                suspicious_targets.append(file_entry)
                
        if suspicious_targets:
            logger.info(f"Target filtration hit detected. Found {len(suspicious_targets)} matching anomalies. Initializing parallel extraction.")
            extraction_results = analyzer.concurrent_artifact_extraction(suspicious_targets, thread_timeout=15.0)
            analyzer._save_checkpoint("EXTRACTION_PIPELINE_COMPLETE")
            
            results["suspicious_files_extracted"] = len(suspicious_targets)
            results["extracted_data"] = extraction_results
            results["status"] = "Success"
        else:
            logger.info("Zero volatile signature filtration target triggers returned from core execution pass.")
            results["status"] = "Success (No anomalous files > 50MB found)"
            
    return results


def _parse_fls_line(line: str) -> dict | None:
    """Parse a single fls output line into a structured dict.
    fls -l output format:  type inode\tname\tmod\tacc\tchg\tcre\tsize\tuid\tgid
    fls short output:      type inode:\tname
    """
    if not line.strip():
        return None

    is_deleted = line.startswith('*') or '(deleted)' in line

    # Try long-format first (tab-separated with >= 7 fields)
    parts = line.split('\t')
    if len(parts) >= 7:
        type_inode = parts[0].split()
        entry_type = type_inode[0] if type_inode else 'unknown'
        inode = type_inode[1].rstrip(':') if len(type_inode) > 1 else ''
        path = parts[1].strip().lstrip('/')
        name = os.path.basename(path) if path else ''
        size_str = parts[6].strip() if len(parts) > 6 else '0'
        size = int(size_str) if size_str.isdigit() else 0
        mod_time = parts[2].strip() if len(parts) > 2 else ''
        acc_time = parts[3].strip() if len(parts) > 3 else ''
        chg_time = parts[4].strip() if len(parts) > 4 else ''
        cre_time = parts[5].strip() if len(parts) > 5 else ''
    else:
        # Short format: "type inode:\tpath"
        type_inode_part = parts[0].split()
        entry_type = type_inode_part[0] if type_inode_part else 'unknown'
        inode = type_inode_part[1].rstrip(':') if len(type_inode_part) > 1 else ''
        path = parts[1].strip().lstrip('/') if len(parts) > 1 else ''
        name = os.path.basename(path) if path else ''
        size = 0
        mod_time = acc_time = chg_time = cre_time = ''

    if not name or name in ('.', '..'):
        return None

    ext = os.path.splitext(name)[1].lower()

    return {
        'name': name,
        'path': path,
        'inode': inode,
        'size': size,
        'type': entry_type.replace('*', ''),
        'extension': ext,
        'is_deleted': is_deleted,
        'modified': mod_time,
        'accessed': acc_time,
        'changed': chg_time,
        'created': cre_time,
    }


def scan_live_drive_deleted(folder_path: str) -> dict:
    """
    Scan a live Windows drive for deleted files using SleuthKit fls.
    Accepts a folder path (e.g. D:\\burger) or drive root (e.g. D:\\).
    Resolves the drive letter to \\\\.\\D: device path for raw access.
    """
    results = {}

    # Normalise and extract drive letter
    folder_path = os.path.abspath(folder_path)
    drive, remainder = os.path.splitdrive(folder_path)
    if not drive:
        return {'error': f'Could not determine drive letter from: {folder_path}'}

    drive_letter = drive.rstrip(':')
    device_path = f'\\\\.\\{drive_letter}:'

    # Determine sub-folder filter (e.g. "burger/" from D:\burger)
    sub_folder = remainder.strip(os.sep).replace('\\', '/').lower()

    fls = get_sleuthkit_tool('fls')

    try:
        # Run fls -r -l on the device to get ALL files (deleted + existing)
        # We list everything and filter deleted ones ourselves for better results
        proc = run([fls, '-r', '-l', device_path], timeout=300)

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            if 'Permission denied' in stderr or 'Access is denied' in stderr or 'Error opening' in stderr:
                return {
                    'error': 'Access denied reading raw volume. The backend must run as Administrator.',
                    'fix': 'Close the current terminal, open a new one as Administrator, and re-run: uv run .\\main.py',
                    'details': stderr
                }
            return {'error': f'fls failed on {device_path}', 'details': stderr}

        output_lines = proc.stdout.strip().split('\n')

        all_files = []
        deleted_files = []

        for line in output_lines:
            entry = _parse_fls_line(line)
            if not entry:
                continue

            # If user specified a sub-folder, filter to that path
            if sub_folder:
                entry_path_lower = entry['path'].lower()
                if not entry_path_lower.startswith(sub_folder):
                    continue

            all_files.append(entry)
            if entry['is_deleted']:
                deleted_files.append(entry)

        results['status'] = 'Success'
        results['drive'] = f'{drive_letter}:'
        results['device'] = device_path
        results['target_folder'] = folder_path
        results['sub_folder_filter'] = sub_folder or '(entire drive)'
        results['total_files_scanned'] = len(all_files)
        results['deleted_files_found'] = len(deleted_files)
        results['deleted_files'] = deleted_files[:500]
        if len(deleted_files) > 500:
            results['notice'] = f'Showing first 500 of {len(deleted_files)} deleted files.'
        results['summary'] = {
            'by_extension': {},
            'total_deleted_size_bytes': 0,
        }

        for f in deleted_files:
            ext = f['extension'] or '(no extension)'
            results['summary']['by_extension'][ext] = results['summary']['by_extension'].get(ext, 0) + 1
            results['summary']['total_deleted_size_bytes'] += f['size']

        # Human-readable size
        total_bytes = results['summary']['total_deleted_size_bytes']
        if total_bytes >= 1073741824:
            results['summary']['total_deleted_size'] = f'{total_bytes / 1073741824:.2f} GB'
        elif total_bytes >= 1048576:
            results['summary']['total_deleted_size'] = f'{total_bytes / 1048576:.2f} MB'
        elif total_bytes >= 1024:
            results['summary']['total_deleted_size'] = f'{total_bytes / 1024:.2f} KB'
        else:
            results['summary']['total_deleted_size'] = f'{total_bytes} B'

    except FileNotFoundError:
        results['error'] = 'SleuthKit fls not found. Install SleuthKit and add bin/ to PATH.'
    except Exception as e:
        results['error'] = f'Live drive scan failed: {str(e)}'

    return results


def recover_deleted_file(drive_path: str, inode: str, output_name: str = None) -> dict:
    """
    Recover a single deleted file from a live drive by inode using icat.
    drive_path: e.g. "D:\\" or "D:\\burger"
    inode: the inode number from fls output
    output_name: optional filename; defaults to "recovered_<inode>"
    """
    drive, _ = os.path.splitdrive(os.path.abspath(drive_path))
    if not drive:
        return {'error': f'Could not determine drive letter from: {drive_path}'}

    drive_letter = drive.rstrip(':')
    device_path = f'\\\\.\\{drive_letter}:'

    icat = get_sleuthkit_tool('icat')

    # Create a recovery output directory
    recovery_dir = os.path.join(tempfile.gettempdir(), 'cyberx_recovered')
    os.makedirs(recovery_dir, exist_ok=True)

    safe_name = output_name or f'recovered_{inode}'
    # Sanitise filename
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)
    out_file = os.path.join(recovery_dir, safe_name)

    try:
        proc = subprocess.run(
            [icat, device_path, inode],
            capture_output=True,
            timeout=60
        )

        if proc.returncode != 0:
            stderr = proc.stderr.decode('utf-8', errors='replace').strip()
            if 'Permission denied' in stderr or 'Access is denied' in stderr:
                return {'error': 'Access denied. Run backend as Administrator.', 'details': stderr}
            return {'error': f'icat failed for inode {inode}', 'details': stderr}

        if not proc.stdout:
            return {
                'status': 'Warning',
                'message': f'Inode {inode} returned 0 bytes — file content may have been overwritten.',
                'inode': inode
            }

        with open(out_file, 'wb') as f:
            f.write(proc.stdout)

        # Hash the recovered file
        sha256 = hashlib.sha256(proc.stdout).hexdigest()

        return {
            'status': 'Recovered',
            'inode': inode,
            'output_file': out_file,
            'size_bytes': len(proc.stdout),
            'sha256': sha256,
            'message': f'File recovered successfully to {out_file}'
        }

    except FileNotFoundError:
        return {'error': 'SleuthKit icat not found. Install SleuthKit and add bin/ to PATH.'}
    except subprocess.TimeoutExpired:
        return {'error': f'Recovery timed out for inode {inode}'}
    except Exception as e:
        return {'error': f'Recovery failed: {str(e)}'}


def run_sleuthkit(image_path: str, scan_type: str = "mmls"):
    """
    Uses Sleuth Kit to analyse a disk image or live drive.
    Supports mmls, fsstat, fls, timeline, enterprise, deleted_files — cross-platform (Windows + Linux).
    """
    # For deleted_files mode, delegate to the live-drive scanner (no image file needed)
    if scan_type == "deleted_files":
        return scan_live_drive_deleted(image_path)

    if not os.path.exists(image_path):
        return {"error": f"Disk image file not found: {image_path}"}

    results = {}

    try:
        if scan_type == "enterprise":
            output_dir = os.path.join(tempfile.gettempdir(), f"dfir_ent_output_{int(time.time())}")
            results = run_enterprise_pipeline(image_path, output_dir)
            results['enterprise_output_dir'] = output_dir
            results['notice'] = "Enterprise DFIR pipeline executed. Artifacts extracted to output directory."
            
        elif scan_type == "mmls":
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

analyze_image = run_sleuthkit
