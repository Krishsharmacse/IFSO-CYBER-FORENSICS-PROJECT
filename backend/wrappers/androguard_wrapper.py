import os
import re
import json
import hashlib
import logging
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from collections import defaultdict
import math

# Androguard imports
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK

# Suppress spammy warnings
logging.getLogger("androguard").setLevel(logging.ERROR)
try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

# Configure logging
logger = logging.getLogger(__name__)

# Try importing optional dependencies
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not available - signature-based detection disabled")

try:
    from Crypto.Cipher import AES, DES
    from Crypto.Hash import MD5, SHA1, SHA256
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ThreatLevel(str, Enum):
    """Threat severity levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MALICIOUS = "MALICIOUS"

class AppCategory(str, Enum):
    """Application categories."""
    BANKING = "Banking"
    SOCIAL_MEDIA = "Social Media"
    MESSAGING = "Messaging"
    GAMING = "Gaming"
    TOOLS = "Tools"
    MALWARE = "Malware"
    UNKNOWN = "Unknown"

@dataclass
class PermissionRisk:
    """Permission risk assessment."""
    permission: str
    risk_level: ThreatLevel
    score: int
    description: str
    category: str

@dataclass
class CodePattern:
    """Suspicious code pattern found."""
    pattern_name: str
    severity: ThreatLevel
    description: str
    location: str
    code_snippet: Optional[str] = None

@dataclass
class NetworkIndicator:
    """Network-related indicator."""
    type: str  # URL, IP, Domain, Email
    value: str
    context: str
    risk_score: int

@dataclass
class CertificateInfo:
    """APK signing certificate information."""
    serial_number: str
    issuer: str
    subject: str
    valid_from: str
    valid_to: str
    fingerprint_md5: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    is_debug: bool
    is_self_signed: bool

@dataclass
class APKMetadata:
    """Comprehensive APK metadata."""
    file_path: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    app_name: str
    package_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    max_sdk: int
    main_activity: str
    activities_count: int
    services_count: int
    receivers_count: int
    providers_count: int
    permissions_count: int
    dex_files_count: int
    certificate: Optional[CertificateInfo] = None

@dataclass
class ThreatAnalysis:
    """Complete threat analysis results."""
    verdict: ThreatLevel
    threat_score: int
    confidence_score: float
    flags: List[str] = field(default_factory=list)
    permissions_risks: List[PermissionRisk] = field(default_factory=list)
    code_patterns: List[CodePattern] = field(default_factory=list)
    network_indicators: List[NetworkIndicator] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    anti_analysis_detected: bool = False
    encryption_misuse: List[str] = field(default_factory=list)

@dataclass
class APKAnalysisResult:
    """Complete APK analysis results."""
    status: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Optional[APKMetadata] = None
    threat_analysis: Optional[ThreatAnalysis] = None
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    error: Optional[str] = None
    analysis_duration: float = 0.0


# ============================================================================
# Threat Intelligence Database
# ============================================================================

class ThreatIntelligence:
    """Threat intelligence database for APK analysis."""
    
    # Known malicious package names (partials)
    MALICIOUS_PACKAGE_PATTERNS = [
        r'.*\.malware\..*',
        r'.*\.spy\..*',
        r'.*\.sms\..*',
        r'.*\.stealer\..*',
        r'.*\.bank\..*',
        r'.*\.ransom.*',
    ]
    
    # Known fake app impersonations
    IMPERSONATION_TARGETS = {
        'whatsapp': {
            'legitimate_packages': ['com.whatsapp', 'com.whatsapp.w4b'],
            'category': AppCategory.MESSAGING,
            'threat_score': 100
        },
        'instagram': {
            'legitimate_packages': ['com.instagram.android'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 100
        },
        'facebook': {
            'legitimate_packages': ['com.facebook.katana', 'com.facebook.orca'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 100
        },
        'telegram': {
            'legitimate_packages': ['org.telegram.messenger'],
            'category': AppCategory.MESSAGING,
            'threat_score': 100
        },
        'snapchat': {
            'legitimate_packages': ['com.snapchat.android'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 100
        },
        'tiktok': {
            'legitimate_packages': ['com.zhiliaoapp.musically', 'com.ss.android.ugc.trill'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 100
        },
        'twitter': {
            'legitimate_packages': ['com.twitter.android'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 90
        },
        'netflix': {
            'legitimate_packages': ['com.netflix.mediaclient'],
            'category': AppCategory.TOOLS,
            'threat_score': 100
        },
        'paypal': {
            'legitimate_packages': ['com.paypal.android.p2pmobile'],
            'category': AppCategory.BANKING,
            'threat_score': 100
        },
        'spotify': {
            'legitimate_packages': ['com.spotify.music'],
            'category': AppCategory.TOOLS,
            'threat_score': 90
        },
        'amazon': {
            'legitimate_packages': ['com.amazon.mShop.android.shopping'],
            'category': AppCategory.TOOLS,
            'threat_score': 90
        },
        'gmail': {
            'legitimate_packages': ['com.google.android.gm'],
            'category': AppCategory.TOOLS,
            'threat_score': 100
        },
        'youtube': {
            'legitimate_packages': ['com.google.android.youtube'],
            'category': AppCategory.SOCIAL_MEDIA,
            'threat_score': 90
        },
        'chrome': {
            'legitimate_packages': ['com.android.chrome'],
            'category': AppCategory.TOOLS,
            'threat_score': 90
        },
    }
    
    # High-risk permissions with detailed risk assessment
    PERMISSION_RISKS = {
        # Privacy Invasion
        'android.permission.READ_SMS': PermissionRisk(
            permission='READ_SMS',
            risk_level=ThreatLevel.HIGH,
            score=25,
            description='Can read SMS messages (OTP stealing, 2FA bypass)',
            category='Privacy'
        ),
        'android.permission.SEND_SMS': PermissionRisk(
            permission='SEND_SMS',
            risk_level=ThreatLevel.HIGH,
            score=25,
            description='Can send SMS messages (Premium SMS fraud)',
            category='Privacy'
        ),
        'android.permission.RECEIVE_SMS': PermissionRisk(
            permission='RECEIVE_SMS',
            risk_level=ThreatLevel.HIGH,
            score=20,
            description='Can receive SMS messages (Intercept verification codes)',
            category='Privacy'
        ),
        'android.permission.READ_CONTACTS': PermissionRisk(
            permission='READ_CONTACTS',
            risk_level=ThreatLevel.MEDIUM,
            score=15,
            description='Can read contacts (Data harvesting)',
            category='Privacy'
        ),
        'android.permission.READ_CALL_LOG': PermissionRisk(
            permission='READ_CALL_LOG',
            risk_level=ThreatLevel.MEDIUM,
            score=15,
            description='Can read call history',
            category='Privacy'
        ),
        
        # Surveillance
        'android.permission.CAMERA': PermissionRisk(
            permission='CAMERA',
            risk_level=ThreatLevel.MEDIUM,
            score=10,
            description='Can access camera (Potential spyware)',
            category='Surveillance'
        ),
        'android.permission.RECORD_AUDIO': PermissionRisk(
            permission='RECORD_AUDIO',
            risk_level=ThreatLevel.MEDIUM,
            score=10,
            description='Can record audio (Potential eavesdropping)',
            category='Surveillance'
        ),
        'android.permission.ACCESS_FINE_LOCATION': PermissionRisk(
            permission='ACCESS_FINE_LOCATION',
            risk_level=ThreatLevel.MEDIUM,
            score=8,
            description='Can access precise GPS location',
            category='Surveillance'
        ),
        
        # System Manipulation
        'android.permission.SYSTEM_ALERT_WINDOW': PermissionRisk(
            permission='SYSTEM_ALERT_WINDOW',
            risk_level=ThreatLevel.HIGH,
            score=30,
            description='Can draw overlays (Overlay attacks, phishing)',
            category='System'
        ),
        'android.permission.BIND_ACCESSIBILITY_SERVICE': PermissionRisk(
            permission='BIND_ACCESSIBILITY_SERVICE',
            risk_level=ThreatLevel.CRITICAL,
            score=35,
            description='Can use accessibility services (Keylogging, UI manipulation)',
            category='System'
        ),
        'android.permission.BIND_DEVICE_ADMIN': PermissionRisk(
            permission='BIND_DEVICE_ADMIN',
            risk_level=ThreatLevel.HIGH,
            score=30,
            description='Can act as device administrator (Hard to uninstall)',
            category='System'
        ),
        'android.permission.REQUEST_INSTALL_PACKAGES': PermissionRisk(
            permission='REQUEST_INSTALL_PACKAGES',
            risk_level=ThreatLevel.HIGH,
            score=20,
            description='Can install packages (Dropper functionality)',
            category='System'
        ),
        
        # Financial
        'android.permission.PROCESS_OUTGOING_CALLS': PermissionRisk(
            permission='PROCESS_OUTGOING_CALLS',
            risk_level=ThreatLevel.MEDIUM,
            score=10,
            description='Can intercept outgoing calls',
            category='Financial'
        ),
        'android.permission.READ_PHONE_STATE': PermissionRisk(
            permission='READ_PHONE_STATE',
            risk_level=ThreatLevel.MEDIUM,
            score=8,
            description='Can read phone state and IMEI',
            category='Privacy'
        ),
    }
    
    # Suspicious API calls and patterns
    SUSPICIOUS_API_PATTERNS = {
        'runtime_exec': re.compile(r'Runtime\.exec|ProcessBuilder', re.IGNORECASE),
        'reflection': re.compile(r'java\.lang\.reflect\.Method.*invoke', re.IGNORECASE),
        'dex_classloader': re.compile(r'DexClassLoader|PathClassLoader', re.IGNORECASE),
        'native_code': re.compile(r'System\.loadLibrary|System\.load', re.IGNORECASE),
        'crypto_weak': re.compile(r'DES|MD5|RC4', re.IGNORECASE),
        'root_detection': re.compile(r'which\s+su|test-keys|Superuser\.apk', re.IGNORECASE),
        'emulator_detection': re.compile(r'qemu\.hw\.mainkeys|ro\.kernel\.qemu', re.IGNORECASE),
        'debug_detection': re.compile(r'android\.os\.Debug\.isDebuggerConnected', re.IGNORECASE),
        'ssl_bypass': re.compile(r'X509TrustManager.*checkServerTrusted', re.IGNORECASE),
        'webview_js': re.compile(r'addJavascriptInterface|setWebContentsDebuggingEnabled', re.IGNORECASE),
        'hide_icon': re.compile(r'setComponentEnabledSetting|PackageManager\.COMPONENT_ENABLED_STATE_DISABLED', re.IGNORECASE),
        'sms_intercept': re.compile(r'SmsManager|smsManager|sendTextMessage|sendMultipartTextMessage', re.IGNORECASE),
        'keylogger': re.compile(r'onKeyDown|onKeyUp|dispatchKeyEvent', re.IGNORECASE),
        'screen_record': re.compile(r'MediaProjection|createVirtualDisplay', re.IGNORECASE),
    }
    
    # Network indicators patterns
    NETWORK_PATTERNS = {
        'url': re.compile(r'https?://[^\s\'"]+', re.IGNORECASE),
        'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'domain': re.compile(r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s\'"]*)?'),
    }
    
    # Known malicious IPs and domains (expandable database)
    MALICIOUS_INDICATORS = {
        'domains': [
            'malware.com', 'stealer.net', 'ransomware.org',
            # Add more known malicious domains
        ],
        'ip_ranges': [
            '91.234.', '185.130.', '5.45.',
            # Add known malicious IP ranges
        ],
    }
    
    # Tracking/Ad network identifiers
    TRACKING_NETWORKS = {
        'applovin': {'score': 10, 'type': 'Advertising'},
        'appmetrica': {'score': 20, 'type': 'Analytics'},
        'adjust': {'score': 5, 'type': 'Analytics'},
        'amplitude': {'score': 5, 'type': 'Analytics'},
        'appsflyer': {'score': 5, 'type': 'Analytics'},
        'braze': {'score': 5, 'type': 'Analytics'},
        'bugsnag': {'score': 5, 'type': 'Crash Reporting'},
        'clevertap': {'score': 10, 'type': 'Analytics'},
        'crashlytics': {'score': 5, 'type': 'Crash Reporting'},
        'firebase': {'score': 5, 'type': 'Analytics'},
        'flurry': {'score': 10, 'type': 'Analytics'},
        'google_analytics': {'score': 5, 'type': 'Analytics'},
        'hockeyapp': {'score': 5, 'type': 'Crash Reporting'},
        'leanplum': {'score': 10, 'type': 'Analytics'},
        'mixpanel': {'score': 10, 'type': 'Analytics'},
        'moengage': {'score': 10, 'type': 'Analytics'},
        'onesignal': {'score': 5, 'type': 'Push Notifications'},
        'segment': {'score': 10, 'type': 'Analytics'},
        'singular': {'score': 10, 'type': 'Analytics'},
    }
    
    # YARA rules for malware detection
    YARA_RULES = """
    rule Android_Malware_DexClassLoader {
        strings:
            $s1 = "DexClassLoader" nocase
            $s2 = "loadClass" nocase
        condition:
            any of them
    }
    
    rule Android_Malware_DynamicDex {
        strings:
            $s1 = "classes.dex" nocase
            $s2 = "openRawResource" nocase
            $s3 = "AssetManager" nocase
        condition:
            2 of them
    }
    
    rule Android_Banker_Cerberus {
        strings:
            $s1 = "accessibility" nocase
            $s2 = "onAccessibilityEvent" nocase
            $s3 = "getRootInActiveWindow" nocase
        condition:
            all of them
    }
    
    rule Android_Spyware_SpyNote {
        strings:
            $s1 = "SpyNote" nocase
            $s2 = "socket.io" nocase
            $s3 = "rat" nocase
        condition:
            2 of them
    }
    """
    
    @classmethod
    def check_impersonation(cls, app_name: str, package_name: str) -> List[Dict]:
        """Check if app is impersonating legitimate applications."""
        flags = []
        app_name_lower = app_name.lower()
        
        for target, info in cls.IMPERSONATION_TARGETS.items():
            if target in app_name_lower and package_name not in info['legitimate_packages']:
                flags.append({
                    'type': 'impersonation',
                    'severity': ThreatLevel.MALICIOUS if info['threat_score'] >= 100 else ThreatLevel.HIGH,
                    'description': f"App impersonating {target.title()}: claims to be '{app_name}' but package is '{package_name}'",
                    'score': info['threat_score'],
                    'category': info['category'].value
                })
        
        return flags
    
    @classmethod
    def assess_permissions(cls, permissions: List[str]) -> List[PermissionRisk]:
        """Assess risk of requested permissions."""
        risks = []
        for perm in permissions:
            perm_key = perm.split('.')[-1] if '.' in perm else perm
            if perm in cls.PERMISSION_RISKS:
                risks.append(cls.PERMISSION_RISKS[perm])
            elif any(pattern in perm.lower() for pattern in ['admin', 'root', 'system']):
                risks.append(PermissionRisk(
                    permission=perm,
                    risk_level=ThreatLevel.MEDIUM,
                    score=10,
                    description='Potentially dangerous system permission',
                    category='System'
                ))
        return risks
    
    @classmethod
    def find_code_patterns(cls, code_strings: str) -> List[CodePattern]:
        """Find suspicious code patterns in strings."""
        patterns = []
        for pattern_name, regex in cls.SUSPICIOUS_API_PATTERNS.items():
            matches = regex.findall(code_strings)
            if matches:
                severity = ThreatLevel.HIGH if pattern_name in ['runtime_exec', 'dex_classloader', 'ssl_bypass'] else ThreatLevel.MEDIUM
                patterns.append(CodePattern(
                    pattern_name=pattern_name,
                    severity=severity,
                    description=f"Found {len(matches)} instances of {pattern_name}",
                    location='strings analysis',
                    code_snippet=matches[0][:100] if matches else None
                ))
        return patterns
    
    @classmethod
    def extract_network_indicators(cls, text: str) -> List[NetworkIndicator]:
        """Extract network indicators from text."""
        indicators = []
        
        for indicator_type, regex in cls.NETWORK_PATTERNS.items():
            matches = regex.findall(text)
            for match in matches[:20]:  # Limit to prevent flooding
                risk_score = 0
                if any(domain in match for domain in cls.MALICIOUS_INDICATORS['domains']):
                    risk_score = 80
                elif any(match.startswith(ip_range) for ip_range in cls.MALICIOUS_INDICATORS['ip_ranges']):
                    risk_score = 80
                
                indicators.append(NetworkIndicator(
                    type=indicator_type,
                    value=match,
                    context='Extracted from code',
                    risk_score=risk_score
                ))
        
        return indicators


# ============================================================================
# Advanced APK Analyzer
# ============================================================================

class AdvancedAPKAnalyzer:
    """Advanced APK analysis with deep inspection capabilities."""
    
    def __init__(self, file_path: str, deep_analysis: bool = False):
        self.file_path = file_path
        self.deep_analysis = deep_analysis
        self.apk = None
        self.dalvik_vm = None
        self.analysis = None
        self.vm_analysis = None
        self.all_strings = []
        
    def _load_apk(self) -> None:
        """Load and parse APK file."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"APK file not found: {self.file_path}")
        
        self.apk = APK(self.file_path)
        
        if self.deep_analysis:
            try:
                self.apk, [self.dalvik_vm], self.vm_analysis = AnalyzeAPK(self.file_path)
            except Exception as e:
                logger.warning(f"Deep analysis failed: {e}, falling back to basic analysis")
    
    def extract_metadata(self) -> APKMetadata:
        """Extract comprehensive metadata from APK."""
        if not self.apk:
            self._load_apk()
        
        # Calculate file hashes
        file_size = os.path.getsize(self.file_path)
        hashes = self._calculate_hashes()
        
        # Extract certificate info
        cert_info = self._extract_certificate_info()
        
        # Count dex files
        dex_count = 0
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                dex_count = len([f for f in zf.namelist() if f.endswith('.dex')])
        except Exception:
            dex_count = 1  # Default assumption
        
        return APKMetadata(
            file_path=self.file_path,
            file_size=file_size,
            md5=hashes['md5'],
            sha1=hashes['sha1'],
            sha256=hashes['sha256'],
            app_name=self.apk.get_app_name() or 'Unknown',
            package_name=self.apk.get_package() or 'Unknown',
            version_name=self.apk.get_androidversion_name() or 'Unknown',
            version_code=str(self.apk.get_androidversion_code() or 'Unknown'),
            min_sdk=int(self.apk.get_min_sdk_version() or 0),
            target_sdk=int(self.apk.get_target_sdk_version() or 0),
            max_sdk=int(self.apk.get_max_sdk_version() or 0),
            main_activity=self.apk.get_main_activity() or 'Unknown',
            activities_count=len(self.apk.get_activities()),
            services_count=len(self.apk.get_services()),
            receivers_count=len(self.apk.get_receivers()),
            providers_count=len(self.apk.get_providers()),
            permissions_count=len(self.apk.get_permissions()),
            dex_files_count=dex_count,
            certificate=cert_info
        )
    
    def _calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes."""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hashes: {e}")
        return hashes
    
    def _extract_certificate_info(self) -> Optional[CertificateInfo]:
        """Extract signing certificate information."""
        try:
            cert = self.apk.get_certificate()
            if cert:
                return CertificateInfo(
                    serial_number=str(cert.serial_number),
                    issuer=str(cert.issuer),
                    subject=str(cert.subject),
                    valid_from=str(cert.not_valid_before) if hasattr(cert, 'not_valid_before') else 'Unknown',
                    valid_to=str(cert.not_valid_after) if hasattr(cert, 'not_valid_after') else 'Unknown',
                    fingerprint_md5=cert.fingerprint('md5') if hasattr(cert, 'fingerprint') else 'Unknown',
                    fingerprint_sha1=cert.fingerprint('sha1') if hasattr(cert, 'fingerprint') else 'Unknown',
                    fingerprint_sha256=cert.fingerprint('sha256') if hasattr(cert, 'fingerprint') else 'Unknown',
                    is_debug='debug' in str(cert.subject).lower(),
                    is_self_signed=cert.issuer == cert.subject
                )
        except Exception as e:
            logger.warning(f"Failed to extract certificate: {e}")
        return None
    
    def extract_all_strings(self) -> List[str]:
        """Extract all strings from DEX and resources."""
        if not self.all_strings:
            strings = []
            
            # Extract from DEX
            if self.dalvik_vm:
                try:
                    for string in self.dalvik_vm.get_strings():
                        if len(string) >= 4:  # Filter short strings
                            strings.append(string)
                except Exception as e:
                    logger.debug(f"Failed to extract DEX strings: {e}")
            
            # Extract from resources
            try:
                with zipfile.ZipFile(self.file_path, 'r') as zf:
                    for filename in zf.namelist():
                        if filename.endswith('.xml') or filename.endswith('.txt'):
                            try:
                                content = zf.read(filename).decode('utf-8', errors='ignore')
                                # Simple string extraction from XML/text
                                found_strings = re.findall(r'[a-zA-Z0-9._/-]{4,}', content)
                                strings.extend(found_strings)
                            except Exception:
                                pass
            except Exception as e:
                logger.debug(f"Failed to extract resource strings: {e}")
            
            self.all_strings = list(set(strings))  # Deduplicate
        
        return self.all_strings
    
    def detect_obfuscation(self) -> bool:
        """Detect if APK is obfuscated."""
        obfuscation_indicators = 0
        
        # Check package structure
        activities = self.apk.get_activities()
        if activities:
            # Check for single-character class names
            short_names = [a.split('.')[-1] for a in activities if len(a.split('.')[-1]) <= 2]
            if len(short_names) > len(activities) * 0.3:  # More than 30% short names
                obfuscation_indicators += 1
            
            # Check for repeated patterns
            main_package = '.'.join(self.apk.get_package().split('.')[:-1])
            non_main_package = [a for a in activities if not a.startswith(main_package)]
            if len(non_main_package) > 0:
                obfuscation_indicators += 1
        
        # Check for ProGuard files
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                if any('proguard' in f.lower() for f in zf.namelist()):
                    obfuscation_indicators += 1
        except Exception:
            pass
        
        return obfuscation_indicators >= 2
    
    def detect_anti_analysis(self) -> bool:
        """Detect anti-analysis techniques."""
        strings = ' '.join(self.extract_all_strings() if self.all_strings else [])
        
        anti_analysis_indicators = [
            'frida', 'xposed', 'substrate', 'cydia',
            'emulator', 'qemu', 'genymotion', 'virtualbox',
            'isDebuggerConnected', 'isDebuggable',
            '/system/app/Superuser.apk', 'magisk',
            'tracerpid', 'TracerPid',
        ]
        
        found = sum(1 for indicator in anti_analysis_indicators if indicator.lower() in strings.lower())
        return found >= 2
    
    def check_encryption_misuse(self) -> List[str]:
        """Check for encryption misuse."""
        issues = []
        strings = ' '.join(self.extract_all_strings() if self.all_strings else [])
        
        # Weak algorithms
        if 'DES' in strings or 'des' in strings:
            issues.append("Uses weak encryption algorithm (DES)")
        if 'MD5' in strings and 'SHA' not in strings:
            issues.append("Uses weak hash algorithm (MD5)")
        if 'RC4' in strings:
            issues.append("Uses weak stream cipher (RC4)")
        
        # Hardcoded keys
        key_patterns = [
            r'(?:key|secret|password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:AES|DES)Key\s*=\s*["\'][^"\']{8,}["\']',
        ]
        for pattern in key_patterns:
            if re.search(pattern, strings, re.IGNORECASE):
                issues.append("Possible hardcoded encryption key found")
                break
        
        return issues
    
    def comprehensive_threat_analysis(self) -> ThreatAnalysis:
        """Perform comprehensive threat analysis."""
        if not self.apk:
            self._load_apk()
        
        threat_analysis = ThreatAnalysis(
            verdict=ThreatLevel.SAFE,
            threat_score=0,
            confidence_score=0.0
        )
        
        # 1. Check impersonation
        app_name = self.apk.get_app_name() or ''
        package_name = self.apk.get_package() or ''
        impersonation_flags = ThreatIntelligence.check_impersonation(app_name, package_name)
        for flag in impersonation_flags:
            threat_analysis.flags.append(flag['description'])
            threat_analysis.threat_score += flag['score']
        
        # 2. Assess permissions
        permissions = self.apk.get_permissions()
        permission_risks = ThreatIntelligence.assess_permissions(permissions)
        threat_analysis.permissions_risks = permission_risks
        threat_analysis.threat_score += sum(risk.score for risk in permission_risks)
        
        # Permission-based flags
        if threat_analysis.threat_score > 80:
            threat_analysis.flags.append("CRITICAL: Excessive dangerous permissions requested")
        
        # 3. Analyze code patterns (if deep analysis)
        if self.deep_analysis or self.all_strings:
            strings_text = ' '.join(self.extract_all_strings())
            code_patterns = ThreatIntelligence.find_code_patterns(strings_text)
            threat_analysis.code_patterns = code_patterns
            threat_analysis.threat_score += sum(
                20 if pattern.severity == ThreatLevel.HIGH else 10 
                for pattern in code_patterns
            )
            
            # Network indicators
            network_indicators = ThreatIntelligence.extract_network_indicators(strings_text)
            threat_analysis.network_indicators = network_indicators
            threat_analysis.threat_score += sum(ind.risk_score for ind in network_indicators)
            
            # Obfuscation and anti-analysis
            if self.detect_obfuscation():
                threat_analysis.obfuscation_detected = True
                threat_analysis.threat_score += 10
                threat_analysis.flags.append("Obfuscation detected (potential malware)")
            
            if self.detect_anti_analysis():
                threat_analysis.anti_analysis_detected = True
                threat_analysis.threat_score += 15
                threat_analysis.flags.append("Anti-analysis techniques detected")
            
            # Encryption issues
            encryption_issues = self.check_encryption_misuse()
            threat_analysis.encryption_misuse = encryption_issues
            threat_analysis.threat_score += len(encryption_issues) * 5
        
        # 4. Check tracking networks
        all_components = ' '.join(
            self.apk.get_services() + 
            self.apk.get_receivers() + 
            self.apk.get_providers()
        ).lower()
        
        for network, info in ThreatIntelligence.TRACKING_NETWORKS.items():
            if network in all_components:
                threat_analysis.flags.append(f"Contains {network.replace('_', ' ').title()} {info['type']} SDK")
                threat_analysis.threat_score += info['score']
        
        # 5. Additional heuristic checks
        # Check for suspicious services/receivers count
        services_count = len(self.apk.get_services())
        receivers_count = len(self.apk.get_receivers())
        
        if services_count > 10:
            threat_analysis.threat_score += 5
            threat_analysis.flags.append(f"Unusually high number of services ({services_count})")
        
        if receivers_count > 10:
            threat_analysis.threat_score += 5
            threat_analysis.flags.append(f"Unusually high number of broadcast receivers ({receivers_count})")
        
        # 6. Certificate analysis
        cert_info = self._extract_certificate_info()
        if cert_info:
            if cert_info.is_debug:
                threat_analysis.threat_score += 10
                threat_analysis.flags.append("APK signed with debug certificate")
            
            if cert_info.is_self_signed:
                threat_analysis.threat_score += 5
                threat_analysis.flags.append("APK is self-signed")
        
        # 7. Determine verdict and confidence
        threat_analysis.threat_score = min(threat_analysis.threat_score, 200)  # Cap at 200
        
        if threat_analysis.threat_score >= 150:
            threat_analysis.verdict = ThreatLevel.MALICIOUS
            threat_analysis.confidence_score = 0.95
        elif threat_analysis.threat_score >= 100:
            threat_analysis.verdict = ThreatLevel.CRITICAL
            threat_analysis.confidence_score = 0.85
        elif threat_analysis.threat_score >= 70:
            threat_analysis.verdict = ThreatLevel.HIGH
            threat_analysis.confidence_score = 0.75
        elif threat_analysis.threat_score >= 40:
            threat_analysis.verdict = ThreatLevel.MEDIUM
            threat_analysis.confidence_score = 0.65
        elif threat_analysis.threat_score >= 20:
            threat_analysis.verdict = ThreatLevel.LOW
            threat_analysis.confidence_score = 0.55
        else:
            threat_analysis.verdict = ThreatLevel.SAFE
            threat_analysis.confidence_score = 0.45
        
        # Adjust confidence based on analysis depth
        if not self.deep_analysis:
            threat_analysis.confidence_score *= 0.7  # Lower confidence for basic analysis
        
        return threat_analysis


# ============================================================================
# Main Analysis Functions
# ============================================================================

def analyze_apk(
    file_path: str,
    deep_analysis: bool = False,
    yara_scan: bool = False,
    export_json: bool = False,
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Comprehensive APK analysis with advanced threat detection.
    
    Args:
        file_path: Path to APK file
        deep_analysis: Perform deep DEX analysis (slower but more thorough)
        yara_scan: Use YARA rules for malware detection
        export_json: Export results to JSON file
        output_path: Path for JSON export (default: based on input filename)
    
    Returns:
        Dictionary with complete analysis results
    """
    import time
    start_time = time.time()
    
    result = APKAnalysisResult(
        status="Analysis attempted",
        success=False
    )
    
    try:
        logger.info(f"Starting APK analysis: {file_path}")
        
        # Validate file
        if not os.path.exists(file_path):
            return {"error": f"APK file not found: {file_path}"}
        
        if not file_path.endswith('.apk'):
            logger.warning(f"File may not be an APK: {file_path}")
        
        # Initialize analyzer
        analyzer = AdvancedAPKAnalyzer(file_path, deep_analysis=deep_analysis)
        analyzer._load_apk()
        
        # Extract metadata
        result.metadata = analyzer.extract_metadata()
        
        # Extract components
        result.activities = analyzer.apk.get_activities()
        result.services = analyzer.apk.get_services()
        result.receivers = analyzer.apk.get_receivers()
        result.providers = analyzer.apk.get_providers()
        result.permissions = analyzer.apk.get_permissions()
        
        # Extract libraries
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                lib_files = [f for f in zf.namelist() if f.startswith('lib/')]
                result.libraries = list(set(
                    os.path.basename(f) for f in lib_files if f.endswith('.so')
                ))
        except Exception:
            result.libraries = []
        
        # Perform threat analysis
        result.threat_analysis = analyzer.comprehensive_threat_analysis()
        
        # YARA scan if available and requested
        if yara_scan and YARA_AVAILABLE:
            yara_results = _perform_yara_scan(file_path)
            if yara_results:
                result.threat_analysis.flags.extend(yara_results)
                result.threat_analysis.threat_score += len(yara_results) * 20
                # Recalculate verdict
                if result.threat_analysis.threat_score >= 150:
                    result.threat_analysis.verdict = ThreatLevel.MALICIOUS
        
        result.success = True
        result.status = f"Analysis completed: {result.threat_analysis.verdict.value}"
        
        logger.info(f"APK analysis completed: {result.threat_analysis.verdict.value} "
                   f"(score: {result.threat_analysis.threat_score})")
        
    except Exception as e:
        result.error = str(e)
        result.status = "Analysis failed"
        logger.error(f"APK analysis failed: {e}", exc_info=True)
    
    finally:
        result.analysis_duration = time.time() - start_time
    
    # Convert to dictionary
    result_dict = _result_to_dict(result)
    
    # Export if requested
    if export_json:
        export_path = output_path or f"{os.path.splitext(file_path)[0]}_analysis.json"
        _export_to_json(result_dict, export_path)
    
    return result_dict


def _perform_yara_scan(file_path: str) -> List[str]:
    """Perform YARA rule-based malware scanning."""
    if not YARA_AVAILABLE:
        return []
    
    try:
        rules = yara.compile(source=ThreatIntelligence.YARA_RULES)
        matches = rules.match(file_path)
        return [str(match) for match in matches]
    except Exception as e:
        logger.warning(f"YARA scan failed: {e}")
        return []


def _result_to_dict(result: APKAnalysisResult) -> Dict[str, Any]:
    """Convert result to dictionary for JSON serialization."""
    threat_dict = None
    if result.threat_analysis:
        threat_dict = {
            "verdict": result.threat_analysis.verdict.value,
            "threat_score": result.threat_analysis.threat_score,
            "confidence_score": result.threat_analysis.confidence_score,
            "flags": result.threat_analysis.flags,
            "obfuscation_detected": result.threat_analysis.obfuscation_detected,
            "anti_analysis_detected": result.threat_analysis.anti_analysis_detected,
            "encryption_misuse": result.threat_analysis.encryption_misuse,
            "permissions_risks": [
                asdict(risk) for risk in result.threat_analysis.permissions_risks
            ] if result.threat_analysis.permissions_risks else [],
            "code_patterns": [
                asdict(pattern) for pattern in result.threat_analysis.code_patterns
            ] if result.threat_analysis.code_patterns else [],
            "network_indicators": [
                asdict(indicator) for indicator in result.threat_analysis.network_indicators
            ] if result.threat_analysis.network_indicators else [],
        }
    
    return {
        "status": result.status,
        "success": result.success,
        
        # --- ADDED FOR FRONTEND COMPATIBILITY ---
        "analysis_verdict": result.threat_analysis.verdict.value if result.threat_analysis else "SAFE",
        "threat_score": result.threat_analysis.threat_score if result.threat_analysis else 0,
        "threat_flags": result.threat_analysis.flags if result.threat_analysis else [],
        "app_name": result.metadata.app_name if result.metadata else "Unknown",
        "package": result.metadata.package_name if result.metadata else "Unknown",
        "version_name": result.metadata.version_name if result.metadata else "Unknown",
        "version_code": result.metadata.version_code if result.metadata else "Unknown",
        "permissions": result.permissions,
        "main_activity": result.metadata.main_activity if result.metadata else "Unknown",
        "activities": result.activities,
        "services": result.services,
        "receivers": result.receivers,
        # ----------------------------------------
        
        "timestamp": result.timestamp,
        "analysis_duration_seconds": result.analysis_duration,
        "metadata": asdict(result.metadata) if result.metadata else None,
        "threat_analysis": threat_dict,
        "components": {
            "activities": result.activities,
            "services": result.services,
            "receivers": result.receivers,
            "providers": result.providers,
        },
        "permissions": result.permissions,
        "libraries": result.libraries,
        "error": result.error,
    }


def _export_to_json(data: Dict[str, Any], output_path: str) -> None:
    """Export analysis results to JSON file."""
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Analysis results exported to {output_path}")
    except Exception as e:
        logger.error(f"Failed to export results: {e}")


# Quick analysis alias for backward compatibility
analyze_apk_quick = lambda fp: analyze_apk(fp, deep_analysis=False)


# ============================================================================
# Command Line Interface
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Advanced APK Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --deep --yara
  %(prog)s app.apk --export results.json
        """
    )
    
    parser.add_argument("file", help="Path to APK file")
    parser.add_argument("--deep", action="store_true", 
                       help="Perform deep DEX analysis (slower)")
    parser.add_argument("--yara", action="store_true",
                       help="Use YARA rules for malware detection")
    parser.add_argument("--export", metavar="OUTPUT",
                       help="Export results to JSON file")
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress detailed output")
    
    args = parser.parse_args()
    
    # Perform analysis
    result = analyze_apk(
        file_path=args.file,
        deep_analysis=args.deep,
        yara_scan=args.yara,
        export_json=bool(args.export),
        output_path=args.export
    )
    
    # Print results
    if not args.quiet:
        print("\\n" + "="*60)
        print(f"APK Security Analysis: {os.path.basename(args.file)}")
        print("="*60)
        
        if result.get('success'):
            threat = result['threat_analysis']
            print(f"\\nVerdict: {threat['verdict']}")
            print(f"Threat Score: {threat['threat_score']}/200")
            print(f"Confidence: {threat['confidence_score']:.1%}")
            
            if threat['flags']:
                print("\\nThreat Flags:")
                for flag in threat['flags']:
                    print(f"  • {flag}")
            
            metadata = result['metadata']
            if metadata:
                print(f"\\nPackage: {metadata['package_name']}")
                print(f"Version: {metadata['version_name']} ({metadata['version_code']})")
                print(f"Min SDK: {metadata['min_sdk']}, Target SDK: {metadata['target_sdk']}")
                print(f"Permissions: {metadata['permissions_count']}")
                print(f"Activities: {metadata['activities_count']}")
                print(f"Services: {metadata['services_count']}")
                
                if metadata.get('certificate'):
                    print(f"\\nCertificate:")
                    print(f"  Issuer: {metadata['certificate']['issuer']}")
                    print(f"  Debug: {metadata['certificate']['is_debug']}")
                    print(f"  Self-signed: {metadata['certificate']['is_self_signed']}")
            
            print(f"\\nAnalysis completed in {result['analysis_duration_seconds']:.2f}s")
        else:
            print(f"\\nAnalysis failed: {result.get('error', 'Unknown error')}")
        
        print("="*60)
    else:
        # Quiet mode - print JSON
        print(json.dumps(result, indent=2, default=str))
