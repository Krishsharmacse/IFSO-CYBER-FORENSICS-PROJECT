"""
Advanced Sleuth Kit Forensic Analyzer (Enterprise Edition)
A highly resilient, memory-optimized, and SIEM-integrated DFIR wrapper.
"""

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

# ============================================================================
# Structured SIEM & Chain of Custody Logging
# ============================================================================

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

# Logger initialization
logger = logging.getLogger("DFIR_Enterprise")
log_handler = logging.StreamHandler()
log_handler.setFormatter(SIEMJSONFormatter())
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

# ============================================================================
# Enums and Data Models
# ============================================================================

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

# ============================================================================
# Core Resilient Analyzer Engine
# ============================================================================

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

    # --- Context Manager Protocol ---
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
            
        return False  # Propagate exceptions normally

    # --- Audit & Integrity Controls ---
    def _generate_audit_trail(self, event_type: str, target: str):
        """Calculates running validation logs to protect the Chain of Custody."""
        try:
            target_hash = ""
            if os.path.isfile(target) and event_type == "ANALYZER_INITIALIZED":
                # Only hash on initialization for performance stability
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

    # --- Resiliency & Checkpoint Recovery ---
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

    # --- Memory-Optimized Streaming Methods ---
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

        # Utilize sub-process stdout pipe streaming directly
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

    # --- Asynchronous Worker Pipelines ---
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
                # Enforce dynamic timeouts directly via subprocess control structures
                res = subprocess.run(cmd, capture_output=True, timeout=thread_timeout)
                if res.returncode == 0:
                    with open(out_file, 'wb') as f:
                        f.write(res.stdout)
                    return {"success": True, "file": out_file, "entry": asdict(file_entry)}
            except subprocess.TimeoutExpired:
                logger.warning(f"Extraction execution timed out processing Inode: {file_entry.inode}")
            return {"success": False, "inode": file_entry.inode}

        # Cap worker constraints by logic board capacity
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

# ============================================================================
# Operational Workflow Execution Blueprint
# ============================================================================

def run_enterprise_pipeline(image: str, output: str, offset: Optional[int] = None) -> Dict[str, Any]:
    """Execution wrapper leveraging the Context Manager lifecycle interface."""
    results = {"status": "Started", "suspicious_files_extracted": 0, "extracted_data": []}
    
    with SleuthKitAnalyzer(image_path=image, output_dir=output, offset=offset) as analyzer:
        
        # Phase 1: Stream Engine Manifest Parsing
        logger.info("Initializing Generator-driven disk analysis processing stream.")
        suspicious_targets = []
        
        for file_entry in analyzer.stream_file_manifest():
            # Apply runtime filtration heuristics directly on the generator stream
            if file_entry.size > 50 * 1024 * 1024 and file_entry.extension in ['.exe', '.sh', '.bat']:
                file_entry.category = FileCategory.SUSPICIOUS
                suspicious_targets.append(file_entry)
                
        # Phase 2: Asynchronous Multi-threaded extraction loop backed by dynamic runtime constraints
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


# ============================================================================
# Legacy / Existing API Wrapper
# ============================================================================

def run_sleuthkit(image_path: str, scan_type: str = "mmls"):
    """
    Uses Sleuth Kit to analyse a disk image.
    Supports mmls, fsstat, fls, timeline, enterprise — cross-platform (Windows + Linux).
    """
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
