import os
import sys
import json
import shutil
import uuid
import tempfile
import subprocess
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
from contextlib import contextmanager

# Platform-specific imports
try:
    import pefile  # For PE file analysis
except ImportError:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile  # For ELF file analysis
except ImportError:
    ELFFile = None

try:
    import magic  # python-magic for file type detection
except ImportError:
    magic = None

from wrappers.platform_utils import run, GHIDRA_HEADLESS, IS_WINDOWS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exceptions
# ============================================================================

class GhidraAnalysisError(Exception):
    """Base exception for Ghidra analysis errors."""
    pass

class GhidraNotFoundError(GhidraAnalysisError):
    """Raised when Ghidra analyzeHeadless is not found."""
    pass

class GhidraTimeoutError(GhidraAnalysisError):
    """Raised when analysis exceeds timeout."""
    pass

class FileValidationError(GhidraAnalysisError):
    """Raised when input file validation fails."""
    pass


# ============================================================================
# Enums and Data Classes
# ============================================================================

class BinaryFormat(Enum):
    """Binary file formats."""
    PE = "PE"
    ELF = "ELF"
    MACH_O = "Mach-O"
    UNKNOWN = "Unknown"
    RAW = "Raw Binary"

class Architecture(Enum):
    """CPU architectures."""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "ARM"
    ARM64 = "ARM64"
    MIPS = "MIPS"
    UNKNOWN = "Unknown"

@dataclass
class BinaryMetadata:
    """Metadata extracted from binary before Ghidra analysis."""
    file_path: str
    file_size: int
    md5: str
    sha256: str
    format: BinaryFormat = BinaryFormat.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    mime_type: str = "unknown"
    sections: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings_count: int = 0
    
@dataclass
class FunctionInfo:
    """Information about a discovered function."""
    name: str
    address: str
    size: int
    signature: str = ""
    xrefs_from: List[str] = field(default_factory=list)
    xrefs_to: List[str] = field(default_factory=list)

@dataclass
class AnalysisResult:
    """Complete analysis results."""
    status: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Optional[BinaryMetadata] = None
    functions: List[FunctionInfo] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    ghidra_log: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    project_dir: Optional[str] = None
    project_name: Optional[str] = None
    decompiled_code: str = "" # Storing the massive C source code output


# ============================================================================
# File Analysis Utilities
# ============================================================================

class BinaryAnalyzer:
    """Handles pre-Ghidra binary analysis and validation."""
    
    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        """Calculate MD5 and SHA256 hashes of file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                
        return {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    
    @staticmethod
    def detect_format(file_path: str) -> BinaryFormat:
        """Detect binary file format."""
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                
            if magic_bytes[:2] == b'MZ':
                return BinaryFormat.PE
            elif magic_bytes[:4] == b'\x7fELF':
                return BinaryFormat.ELF
            elif magic_bytes[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                      b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                return BinaryFormat.MACH_O
            else:
                return BinaryFormat.UNKNOWN
        except Exception:
            return BinaryFormat.UNKNOWN
    
    @staticmethod
    def detect_architecture_pe(file_path: str) -> Architecture:
        """Detect architecture of PE file."""
        if pefile is None:
            return Architecture.UNKNOWN
        try:
            pe = pefile.PE(file_path)
            machine = pe.FILE_HEADER.Machine
            arch_map = {
                0x014c: Architecture.X86,
                0x8664: Architecture.X86_64,
                0x01c0: Architecture.ARM,
                0xaa64: Architecture.ARM64,
            }
            return arch_map.get(machine, Architecture.UNKNOWN)
        except Exception:
            return Architecture.UNKNOWN
    
    @staticmethod
    def detect_architecture_elf(file_path: str) -> Architecture:
        """Detect architecture of ELF file."""
        if ELFFile is None:
            return Architecture.UNKNOWN
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                machine = elf.get_machine_arch()
                arch_map = {
                    'x86': Architecture.X86,
                    'x64': Architecture.X86_64,
                    'ARM': Architecture.ARM,
                    'AArch64': Architecture.ARM64,
                    'MIPS': Architecture.MIPS,
                }
                return arch_map.get(machine, Architecture.UNKNOWN)
        except Exception:
            return Architecture.UNKNOWN
    
    @staticmethod
    def detect_architecture(file_path: str, binary_format: BinaryFormat) -> Architecture:
        """Detect architecture based on format."""
        if binary_format == BinaryFormat.PE:
            return BinaryAnalyzer.detect_architecture_pe(file_path)
        elif binary_format == BinaryFormat.ELF:
            return BinaryAnalyzer.detect_architecture_elf(file_path)
        return Architecture.UNKNOWN
    
    @staticmethod
    def extract_pe_info(file_path: str) -> Dict[str, Any]:
        """Extract detailed PE information."""
        if pefile is None:
            return {}
        try:
            pe = pefile.PE(file_path)
            info = {
                'sections': [],
                'imports': [],
                'exports': [],
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            }
            
            for section in pe.sections:
                info['sections'].append({
                    'name': section.Name.decode().strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics),
                })
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode() if entry.dll else ''
                    for imp in entry.imports:
                        func_name = imp.name.decode() if imp.name else f'ordinal_{imp.ordinal}'
                        info['imports'].append(f"{dll_name}!{func_name}")
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        info['exports'].append(exp.name.decode())
            
            return info
        except Exception as e:
            logger.warning(f"Failed to extract PE info: {e}")
            return {}
    
    @staticmethod
    def extract_elf_info(file_path: str) -> Dict[str, Any]:
        """Extract detailed ELF information."""
        if ELFFile is None:
            return {}
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                info = {
                    'sections': [],
                    'entry_point': hex(elf.header.e_entry),
                    'elf_type': elf.header.e_type,
                }
                
                for section in elf.iter_sections():
                    info['sections'].append({
                        'name': section.name,
                        'address': hex(section.header.sh_addr),
                        'size': section.header.sh_size,
                        'type': section.header.sh_type,
                    })
                
                return info
        except Exception as e:
            logger.warning(f"Failed to extract ELF info: {e}")
            return {}
    
    @classmethod
    def extract_metadata(cls, file_path: str) -> BinaryMetadata:
        """Extract comprehensive metadata from binary."""
        file_size = os.path.getsize(file_path)
        hashes = cls.calculate_hashes(file_path)
        binary_format = cls.detect_format(file_path)
        architecture = cls.detect_architecture(file_path, binary_format)
        
        mime_type = "unknown"
        if magic:
            try:
                mime_type = magic.from_file(file_path, mime=True)
            except Exception:
                pass
        
        metadata = BinaryMetadata(
            file_path=file_path,
            file_size=file_size,
            md5=hashes['md5'],
            sha256=hashes['sha256'],
            format=binary_format,
            architecture=architecture,
            mime_type=mime_type,
        )
        
        if binary_format == BinaryFormat.PE:
            pe_info = cls.extract_pe_info(file_path)
            metadata.sections = pe_info.get('sections', [])
            metadata.imports = pe_info.get('imports', [])
            metadata.exports = pe_info.get('exports', [])
        elif binary_format == BinaryFormat.ELF:
            elf_info = cls.extract_elf_info(file_path)
            metadata.sections = elf_info.get('sections', [])
        
        try:
            strings_output = subprocess.run(
                ['strings', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            metadata.strings_count = len(strings_output.stdout.splitlines())
        except Exception:
            pass
        
        return metadata


# ============================================================================
# Ghidra Analysis Engine
# ============================================================================

class GhidraAnalyzer:
    """Handles Ghidra headless analysis with advanced options."""
    
    EXPORT_SCRIPT = """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.StringBuilder;

public class export_script extends GhidraScript {
    @Override
    public void run() throws Exception {
        String output_path = System.getenv("GHIDRA_EXPORT_PATH");
        if (output_path == null) {
            output_path = "/tmp/ghidra_export.json";
        }
        output_path = output_path.replace("\\\\\\\\", "/");
        
        StringBuilder json = new StringBuilder();
        json.append("{\\n");
        json.append("  \\"functions\\": [\\n");
        
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        
        StringBuilder decompiledCode = new StringBuilder();
        
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFunc = true;
        
        while (functions.hasNext()) {
            Function func = functions.next();
            
            if (!firstFunc) {
                json.append(",\\n");
            }
            firstFunc = false;
            
            json.append("    {\\n");
            json.append("      \\"name\\": \\"").append(escapeJson(func.getName())).append("\\",\\n");
            json.append("      \\"address\\": \\"").append(func.getEntryPoint().toString()).append("\\",\\n");
            json.append("      \\"signature\\": \\"").append(escapeJson(func.getSignature().getPrototypeString(true))).append("\\",\\n");
            long size = func.getBody() != null ? func.getBody().getNumAddresses() : 0;
            json.append("      \\"size\\": ").append(size).append(",\\n");
            
            json.append("      \\"xrefs_to\\": [");
            Reference[] refs = getReferencesTo(func.getEntryPoint());
            for (int i = 0; i < refs.length; i++) {
                json.append("\\"").append(refs[i].getFromAddress().toString()).append("\\"");
                if (i < refs.length - 1) json.append(", ");
            }
            json.append("]\\n");
            json.append("    }");
            
            if (!func.isExternal() && !func.isThunk()) {
                DecompileResults res = decompInterface.decompileFunction(func, 60, monitor);
                if (res != null && res.getDecompiledFunction() != null) {
                    decompiledCode.append(res.getDecompiledFunction().getC());
                    decompiledCode.append("\\n\\n");
                }
            }
        }
        json.append("\\n  ],\\n");
        
        json.append("  \\"strings\\": [\\n");
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        boolean firstString = true;
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType() != null && data.getDataType().getName().toLowerCase().contains("string")) {
                if (!firstString) json.append(",\\n");
                firstString = false;
                json.append("    \\"").append(escapeJson(data.getDefaultValueRepresentation())).append("\\"");
            }
        }
        json.append("\\n  ],\\n");
        
        json.append("  \\"decompiled_code\\": \\"").append(escapeJson(decompiledCode.toString())).append("\\"\\n");
        json.append("}\\n");
        
        try (PrintWriter file = new PrintWriter(new FileWriter(output_path))) {
            file.write(json.toString());
        }
        
        println("Analysis results exported to " + output_path);
    }
    
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\\\", "\\\\\\\\")
                  .replace("\\"", "\\\\\\"")
                  .replace("\\b", "\\\\b")
                  .replace("\\f", "\\\\f")
                  .replace("\\n", "\\\\n")
                  .replace("\\r", "\\\\r")
                  .replace("\\t", "\\\\t");
    }
}
"""
    
    def __init__(self, timeout: int = 300, keep_project: bool = False):
        self.timeout = timeout
        self.keep_project = keep_project
        
    def _validate_binary(self, file_path: str) -> None:
        """Validate input binary file."""
        if not os.path.exists(file_path):
            raise FileValidationError(f"Binary file not found: {file_path}")
        
        if not os.path.isfile(file_path):
            raise FileValidationError(f"Path is not a file: {file_path}")
        
        if os.path.getsize(file_path) == 0:
            raise FileValidationError(f"File is empty: {file_path}")
        
        if not os.access(file_path, os.R_OK):
            raise FileValidationError(f"File is not readable: {file_path}")
    
    def _get_ghidra_path(self) -> str:
        """Get Ghidra headless path with validation."""
        if not GHIDRA_HEADLESS:
            raise GhidraNotFoundError(
                "Ghidra analyzeHeadless path not configured. "
                "Please set GHIDRA_HEADLESS in platform_utils."
            )
        
        ghidra_path = GHIDRA_HEADLESS

        if os.path.isdir(ghidra_path):
            exec_name = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
            ghidra_path = os.path.join(ghidra_path, "support", exec_name)
        elif IS_WINDOWS and not ghidra_path.endswith('.bat'):
            if os.path.exists(ghidra_path + '.bat'):
                ghidra_path += '.bat'
                
        if not os.path.exists(ghidra_path):
            raise GhidraNotFoundError(f"Ghidra analyzeHeadless executable not found at: {ghidra_path}")
            
        return ghidra_path
    
    @contextmanager
    def _create_project_dir(self):
        """Create and manage temporary project directory."""
        temp_dir = tempfile.mkdtemp(prefix="ghidra_project_")
        try:
            yield temp_dir
        finally:
            if not self.keep_project:
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up project directory: {temp_dir}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup {temp_dir}: {e}")
    
    def _build_command(self, temp_dir: str, project_name: str, 
                      file_path: str, script_path: Optional[str] = None,
                      analysis_options: Optional[List[str]] = None) -> List[str]:
        """Build Ghidra headless command."""
        cmd = [
            self._get_ghidra_path(),
            temp_dir,
            project_name,
            "-import", file_path,
            "-overwrite",
            "-deleteProject",
        ]
        
        cmd.extend(["-max-cpu", "4"])
        
        if script_path:
            script_dir = os.path.dirname(script_path)
            script_name = os.path.basename(script_path)
            cmd.extend(["-scriptPath", script_dir, "-postScript", script_name])
        
        if analysis_options:
            cmd.extend(analysis_options)
        
        return cmd
    
    def _parse_ghidra_log(self, log_output: str) -> Dict[str, List[str]]:
        """Parse Ghidra log output for errors and warnings."""
        parsed = {
            'errors': [],
            'warnings': [],
            'info': [],
        }
        
        for line in log_output.splitlines():
            if not line.strip():
                continue
            
            line_lower = line.lower()
            if 'error' in line_lower or 'exception' in line_lower:
                parsed['errors'].append(line)
            elif 'warn' in line_lower:
                parsed['warnings'].append(line)
            else:
                parsed['info'].append(line)
        
        return parsed
    
    def analyze(self, file_path: str, 
                analysis_options: Optional[List[str]] = None,
                export_script: Optional[str] = None) -> AnalysisResult:
        """
        Perform complete Ghidra headless analysis.
        """
        start_time = time.time()
        result = AnalysisResult(
            status="Analysis attempted",
            success=False,
        )
        
        try:
            self._validate_binary(file_path)
            
            result.metadata = BinaryAnalyzer.extract_metadata(file_path)
            logger.info(f"Analyzing {result.metadata.format.value} binary: {file_path}")
            
            project_name = f"Project_{uuid.uuid4().hex[:8]}"
            
            with self._create_project_dir() as temp_dir:
                result.project_dir = temp_dir if self.keep_project else None
                result.project_name = project_name
                
                script_path = None
                export_data_path = os.path.join(temp_dir, "export_results.json")
                
                if export_script:
                    script_path = os.path.join(temp_dir, "export_script.java")
                    with open(script_path, 'w') as f:
                        f.write(export_script)
                    os.environ['GHIDRA_EXPORT_PATH'] = export_data_path
                
                cmd = self._build_command(
                    temp_dir, project_name, file_path, 
                    script_path, analysis_options
                )
                
                logger.debug(f"Executing: {' '.join(cmd)}")
                
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env={**os.environ, 'GHIDRA_EXPORT_PATH': export_data_path}
                )
                
                log_parsed = self._parse_ghidra_log(process.stdout)
                result.ghidra_log = log_parsed['info'][-20:]
                result.errors = log_parsed['errors']
                result.warnings = log_parsed['warnings']
                
                if process.returncode == 0:
                    result.success = True
                    result.status = "Analysis completed successfully"
                    
                    if export_script and os.path.exists(export_data_path):
                        try:
                            with open(export_data_path, 'r') as f:
                                export_data = json.load(f)
                            
                            for func_data in export_data.get('functions', []):
                                func = FunctionInfo(
                                    name=func_data['name'],
                                    address=func_data['address'],
                                    size=func_data.get('size', 0),
                                    signature=func_data.get('signature', ''),
                                    xrefs_to=func_data.get('xrefs_to', []),
                                )
                                result.functions.append(func)
                            
                            result.strings = export_data.get('strings', [])
                            result.decompiled_code = export_data.get('decompiled_code', '')
                            
                        except Exception as e:
                            logger.error(f"Failed to parse export data: {e}")
                            result.errors.append(f"Export parse error: {e}")
                    
                else:
                    result.errors.append(
                        f"Ghidra returned non-zero exit code: {process.returncode}"
                    )
                    if process.stderr:
                        result.errors.append(process.stderr[-500:])
        
        except FileValidationError as e:
            result.errors.append(str(e))
            result.status = "File validation failed"
            logger.error(str(e))
            
        except GhidraNotFoundError as e:
            result.errors.append(str(e))
            result.status = "Ghidra not found"
            logger.error(str(e))
            
        except subprocess.TimeoutExpired:
            result.errors.append(f"Analysis timed out after {self.timeout} seconds")
            result.status = "Timeout"
            logger.error(f"Analysis timeout for {file_path}")
            
        except Exception as e:
            result.errors.append(f"Unexpected error: {str(e)}")
            result.status = "Analysis failed"
            logger.exception(f"Unexpected error during analysis: {e}")
        
        finally:
            result.duration_seconds = time.time() - start_time
            if 'GHIDRA_EXPORT_PATH' in os.environ:
                del os.environ['GHIDRA_EXPORT_PATH']
        
        return result


# ============================================================================
# Main Interface Functions
# ============================================================================

def run_headless_analysis(
    file_path: str,
    timeout: int = 300,
    keep_project: bool = False,
    advanced_options: bool = False,
    extract_code: bool = True,  # Added this to match main.py compatibility
) -> Dict[str, Any]:
    """
    Main interface for Ghidra headless analysis.
    """
    analyzer = GhidraAnalyzer(
        timeout=timeout,
        keep_project=keep_project
    )
    
    analysis_options = None
    if advanced_options:
        analysis_options = [
            "-analysisTimeoutPerFile", str(timeout)
        ]
    
    # Run export script if requested
    export_script = GhidraAnalyzer.EXPORT_SCRIPT if extract_code else None
    
    result = analyzer.analyze(
        file_path=file_path,
        analysis_options=analysis_options,
        export_script=export_script
    )
    
    return _result_to_dict(result)


def quick_scan(file_path: str) -> Dict[str, Any]:
    """
    Quick scan without full Ghidra analysis - just metadata extraction.
    """
    try:
        metadata = BinaryAnalyzer.extract_metadata(file_path)
        return {
            "success": True,
            "metadata": asdict(metadata),
            "message": "Quick scan completed"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def batch_analyze(file_paths: List[str], **kwargs) -> List[Dict[str, Any]]:
    """
    Analyze multiple files in batch.
    """
    results = []
    for file_path in file_paths:
        logger.info(f"Analyzing {file_path}...")
        result = run_headless_analysis(file_path, **kwargs)
        results.append(result)
    
    return results


# ============================================================================
# Utility Functions
# ============================================================================

def _result_to_dict(result: AnalysisResult) -> Dict[str, Any]:
    """Convert AnalysisResult to dictionary for JSON serialization."""
    
    metadata_dict = asdict(result.metadata) if result.metadata else None
    if metadata_dict:
        metadata_dict['format'] = result.metadata.format.value if result.metadata.format else "Unknown"
        metadata_dict['architecture'] = result.metadata.architecture.value if result.metadata.architecture else "Unknown"

    return {
        "status": result.status,
        "success": result.success,
        "timestamp": result.timestamp,
        "duration_seconds": result.duration_seconds,
        "metadata": metadata_dict,
        "functions_count": len(result.functions),
        "functions": [asdict(f) for f in result.functions[:100]],  # Limit to 100 functions
        "strings": result.strings[:500],  # Limit to 500 strings
        "ghidra_log": result.ghidra_log,
        "errors": result.errors,
        "warnings": result.warnings,
        "project_name": result.project_name,
        "decompiled_code": result.decompiled_code, # Added decompiled code!
    }


def save_analysis_to_file(result: Dict[str, Any], output_path: str) -> None:
    """Save analysis results to JSON file."""
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    logger.info(f"Analysis results saved to {output_path}")


# Alias for backward compatibility with main.py
analyze_binary = run_headless_analysis
