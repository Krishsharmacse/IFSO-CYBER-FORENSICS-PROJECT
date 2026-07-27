import os
import requests
import math
import base64
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field


MOBSF_URL = "http://127.0.0.1:8001"
MOBSF_API_KEY = "fixed-mobsf-api-key"


@dataclass
class RiskFeatures:
    """Container for extracted risk features"""
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    dangerous_perms: List[str] = field(default_factory=list)
    permission_combinations: List[str] = field(default_factory=list)
    has_packer: bool = False
    packer_name: str = ""
    has_anti_vm: bool = False
    has_anti_debug: bool = False
    has_anti_hook: bool = False
    has_reflection: bool = False
    has_obfuscation: bool = False
    has_cleartext_traffic: bool = False
    has_cert_pinning_bypass: bool = False
    trusts_user_ca: bool = False
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0
    vt_positives: int = 0
    vt_total: int = 0
    malware_permissions: List[str] = field(default_factory=list)
    cert_issues: int = 0
    cert_expired: bool = False
    cert_validity_days: int = 0
    hardcoded_secrets: List[str] = field(default_factory=list)
    is_debuggable: bool = False
    has_backup: bool = False
    has_secure_flag: bool = False
    trackers: List[str] = field(default_factory=list)
    dangerous_apis: List[str] = field(default_factory=list)
    native_libs: int = 0
    H: int = 0
    M: int = 0
    DP: int = 0
    EC: int = 0
    AV: int = 0
    AD: int = 0
    PK: int = 0
    CT: int = 0
    CI: int = 0
    MS: int = 0
    OB: int = 0


class PermissionCombinationDetector:
    """Detect malicious permission combinations"""
    
    MALICIOUS_PATTERNS = {
        'sms_malware': {
            'permissions': [
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECEIVE_SMS'
            ],
            'weight': 25,
            'description': 'SMS malware pattern - can read, send, and receive SMS'
        },
        'overlay_installer': {
            'permissions': [
                'android.permission.SYSTEM_ALERT_WINDOW',
                'android.permission.REQUEST_INSTALL_PACKAGES'
            ],
            'weight': 20,
            'description': 'Overlay + installer - can display overlays and install apps'
        },
        'spyware': {
            'permissions': [
                'android.permission.READ_CONTACTS',
                'android.permission.READ_CALL_LOG',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.RECORD_AUDIO'
            ],
            'weight': 22,
            'description': 'Spyware pattern - contacts, location, and audio access'
        },
        'financial_malware': {
            'permissions': [
                'android.permission.SYSTEM_ALERT_WINDOW',
                'android.permission.READ_SMS',
                'android.permission.RECEIVE_SMS'
            ],
            'weight': 18,
            'description': 'Financial malware - SMS + overlay for phishing'
        },
        'device_admin': {
            'permissions': [
                'android.permission.BIND_DEVICE_ADMIN',
                'android.permission.WRITE_SETTINGS'
            ],
            'weight': 15,
            'description': 'Device admin privileges - can lock/reset device'
        },
        'complete_control': {
            'permissions': [
                'android.permission.READ_PHONE_STATE',
                'android.permission.SYSTEM_ALERT_WINDOW',
                'android.permission.REQUEST_INSTALL_PACKAGES',
                'android.permission.WRITE_SETTINGS'
            ],
            'weight': 30,
            'description': 'Complete control - read phone, overlay, install packages, change settings'
        },
        'data_exfiltration': {
            'permissions': [
                'android.permission.READ_CONTACTS',
                'android.permission.READ_SMS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_EXTERNAL_STORAGE'
            ],
            'weight': 20,
            'description': 'Data exfiltration - contacts, SMS, location, files'
        }
    }
    
    def __init__(self):
        self.detected_patterns = []
        
    def analyze(self, permissions: List[str]) -> Tuple[List[Dict], int]:
        """Analyze permissions for malicious combinations"""
        detected = []
        total_weight = 0
        perm_set = set(permissions)
        
        for pattern_name, pattern_info in self.MALICIOUS_PATTERNS.items():
            required_perms = set(pattern_info['permissions'])
            if required_perms.issubset(perm_set):
                detected.append({
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'weight': pattern_info['weight']
                })
                total_weight += pattern_info['weight']
        
        return detected, total_weight


class MobSFAnalyzer:
    """Enhanced MobSF analyzer with corrected risk prediction"""
    
    def __init__(self):
        self.MOBSF_URL = MOBSF_URL
        self.MOBSF_API_KEY = MOBSF_API_KEY
        self.permission_detector = PermissionCombinationDetector()
        
        self.FEATURE_WEIGHTS = {
            'high_findings': 0.30,
            'permission_combinations': 0.20,
            'apkid_malware': 0.15,
            'malware_detection': 0.30,
            'network_security': 0.15,
            'exported_components': 0.10,
            'certificate': 0.15,
            'secrets': 0.10,
            'manifest_flags': 0.10
        }
        
        self.APKID_WEIGHTS = {
            'packer': {
                'SecNeo': 25,
                'UPX': 20,
                'ditor': 22,
                '360': 20,
                'tencent': 18,
                'default': 15
            },
            'anti_vm': 20,
            'anti_debug': 20,
            'anti_hook': 15,
            'reflection': 12,
            'obfuscation': 10
        }
        
        self.SEVERITY_WEIGHTS = {
            'high': 25,
            'medium': 10,
            'low': 3,
            'warning': 6
        }
        
        self.NETWORK_WEIGHTS = {
            'cleartext_traffic': 20,
            'cert_pinning_bypass': 25,
            'trust_user_ca': 15,
            'no_https': 15
        }

    def run_mobsf_scan(self, file_path: str) -> Dict[str, Any]:
        """Main analysis entry point with unified online/offline risk calculation"""
        if not os.path.exists(file_path):
            return {"error": f"APK file not found: {file_path}"}
        
        if self.MOBSF_API_KEY == "YOUR_MOBSF_API_KEY":
            return {"error": "MobSF API key not configured"}
        
        report_data = None
        pdf_path = None
        pdf_base64 = None

        mobsf_online = False
        try:
            res = requests.get(self.MOBSF_URL, timeout=3)
            if res.status_code < 500:
                mobsf_online = True
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            mobsf_online = False

        if mobsf_online:
            try:
                upload_data = self._upload_file(file_path)
                if isinstance(upload_data, dict) and 'error' in upload_data:
                    return upload_data
                    
                hash_val = upload_data.get("hash")
                scan_type = upload_data.get("scan_type")
                
                scan_result = self._trigger_scan(hash_val, scan_type)
                if isinstance(scan_result, dict) and 'error' in scan_result:
                    return scan_result
                    
                report_data = self._get_report(hash_val)
                if isinstance(report_data, dict) and 'error' in report_data:
                    return report_data
                
                pdf_path, pdf_base64 = self._download_pdf_with_base64(hash_val)
            except Exception as e:
                mobsf_online = False

        if not mobsf_online or not report_data:
            try:
                from wrappers.mobsf_scan import scan_file
                report_data = scan_file(file_path)
                if isinstance(report_data, dict) and "error" in report_data and report_data.get("status") == "Failed":
                    return report_data
            except Exception as ex:
                return {"error": f"MobSF server offline and local mobsf_scan failed: {ex}"}

        try:
            features = self._extract_features(report_data)
            risk_scores = self._calculate_risk_scores(features)
            final_risk = self._compute_final_risk(risk_scores)
            classification = self._classify_risk(final_risk, risk_scores)
            
            if not pdf_path:
                h_val = report_data.get("hash") or report_data.get("hashes", {}).get("sha256", "mobsf_report")
                pdf_path, pdf_base64 = self._generate_local_pdf(h_val, report_data, features, risk_scores, final_risk, classification)

            return self._build_response(report_data, features, risk_scores, 
                                       final_risk, classification, pdf_path, pdf_base64)
        except Exception as e:
            return {"error": f"Failed to compute MobSF risk report: {str(e)}"}

    def _extract_features(self, report_data: Dict) -> RiskFeatures:
        """Extract all features from MobSF report"""
        features = RiskFeatures()
        features = self._extract_severity_findings(features, report_data)
        features = self._extract_permissions(features, report_data)
        features = self._extract_apkid(features, report_data)
        features = self._extract_network_security(features, report_data)
        features = self._extract_components(features, report_data)
        features = self._extract_malware(features, report_data)
        features = self._extract_certificate(features, report_data)
        features = self._extract_secrets_and_flags(features, report_data)
        features = self._extract_trackers(features, report_data)
        features = self._extract_dangerous_apis(features, report_data)
        
        features.H = features.high_findings
        features.M = features.medium_findings
        features.DP = len(features.dangerous_perms)
        features.EC = (features.exported_activities + features.exported_services + 
                      features.exported_receivers + features.exported_providers)
        features.AV = 1 if features.has_anti_vm else 0
        features.AD = 1 if features.has_anti_debug else 0
        features.PK = 1 if features.has_packer else 0
        features.CT = 1 if features.has_cleartext_traffic else 0
        features.CI = features.cert_issues
        features.MS = features.vt_positives
        features.OB = 1 if features.has_obfuscation else 0
        
        return features

    def _extract_severity_findings(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract severity findings from MobSF server or local sast_findings"""
        # Local scan format
        sast = report_data.get('sast_findings')
        if isinstance(sast, dict):
            features.high_findings += len(sast.get('high', []))
            features.medium_findings += len(sast.get('medium', []))
            features.low_findings += len(sast.get('low', []))

        # MobSF server manifest_analysis
        manifest = report_data.get('manifest_analysis', {})
        if isinstance(manifest, list):
            for item in manifest:
                if isinstance(item, dict):
                    stat = (item.get('stat') or item.get('severity') or '').lower()
                    if stat in ['high', 'critical']:
                        features.high_findings += 1
                    elif stat in ['medium', 'warning']:
                        features.medium_findings += 1
                    elif stat in ['low', 'info']:
                        features.low_findings += 1
        elif isinstance(manifest, dict):
            for key, value in manifest.items():
                if isinstance(value, dict):
                    stat = (value.get('stat') or value.get('severity') or '').lower()
                    if stat in ['high', 'critical']:
                        features.high_findings += 1
                    elif stat in ['medium', 'warning']:
                        features.medium_findings += 1
                    elif stat in ['low', 'info']:
                        features.low_findings += 1

        # MobSF server code_analysis
        code_analysis = report_data.get('code_analysis', {})
        if isinstance(code_analysis, dict):
            for key, value in code_analysis.items():
                if isinstance(value, dict):
                    meta = value.get('metadata', value)
                    if isinstance(meta, dict):
                        stat = (meta.get('severity') or meta.get('stat') or '').lower()
                        if stat in ['high', 'critical']:
                            features.high_findings += 1
                        elif stat in ['medium', 'warning']:
                            features.medium_findings += 1
                        elif stat in ['low', 'info']:
                            features.low_findings += 1

        return features

    def _extract_permissions(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract and analyze permissions from MobSF server or local scan"""
        dangerous_perm_patterns = [
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
            'READ_CONTACTS', 'READ_CALL_LOG',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'CAMERA', 'RECORD_AUDIO',
            'READ_PHONE_STATE', 'PROCESS_OUTGOING_CALLS',
            'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES',
            'WRITE_SETTINGS', 'BIND_DEVICE_ADMIN',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'
        ]

        extracted_perms = set()

        # From local scan or MobSF server permissions
        perms_raw = report_data.get('permissions', [])
        if isinstance(perms_raw, list):
            for p in perms_raw:
                if isinstance(p, dict):
                    name = p.get('name', '')
                    if p.get('is_dangerous') or any(pat in name for pat in dangerous_perm_patterns):
                        extracted_perms.add(name)
                elif isinstance(p, str):
                    if any(pat in p for pat in dangerous_perm_patterns):
                        extracted_perms.add(p)
        elif isinstance(perms_raw, dict):
            for perm_name, info in perms_raw.items():
                is_dang = False
                if isinstance(info, dict):
                    status = str(info.get('status', '')).lower()
                    if status == 'dangerous':
                        is_dang = True
                if is_dang or any(pat in perm_name for pat in dangerous_perm_patterns):
                    extracted_perms.add(perm_name)

        features.dangerous_perms = list(extracted_perms)

        patterns, _ = self.permission_detector.analyze(features.dangerous_perms)
        features.permission_combinations = [p['description'] for p in patterns]

        return features

    def _extract_apkid(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract APKID information"""
        apkid = report_data.get('apkid', {})
        if isinstance(apkid, dict):
            for dex, details in apkid.items():
                if isinstance(details, dict):
                    if details.get('packer') in ['yes', True]:
                        features.has_packer = True
                        if 'packer_name' in details:
                            features.packer_name = details['packer_name']
                        else:
                            for key in details.keys():
                                if any(packer in key.lower() for packer in ['secneo', 'upx', 'ditor', '360', 'tencent']):
                                    features.packer_name = key
                                    break
                    
                    if details.get('anti_vm') in ['yes', True]:
                        features.has_anti_vm = True
                    if details.get('anti_debug') in ['yes', True]:
                        features.has_anti_debug = True
                    if details.get('anti_hook') in ['yes', True]:
                        features.has_anti_hook = True
                    if details.get('reflection') in ['yes', True]:
                        features.has_reflection = True
                    if details.get('obfuscator') in ['yes', True]:
                        features.has_obfuscation = True

        # Also inspect SAST findings for anti-analysis techniques
        sast = report_data.get('sast_findings', {})
        if isinstance(sast, dict):
            all_findings = sast.get('high', []) + sast.get('medium', []) + sast.get('low', [])
            for f in all_findings:
                if isinstance(f, dict):
                    title = str(f.get('title', '')).lower()
                    rule_id = str(f.get('rule_id', '')).lower()
                    if 'anti-vm' in title or 'anti_vm' in rule_id or 'emulator' in title:
                        features.has_anti_vm = True
                    if 'anti-debug' in title or 'anti_debug' in rule_id or 'debugger' in title:
                        features.has_anti_debug = True
                    if 'obfuscat' in title or 'obfuscat' in rule_id:
                        features.has_obfuscation = True

        return features

    def _extract_network_security(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract network security information"""
        manifest = report_data.get('manifest_analysis', {})
        if isinstance(manifest, dict):
            for key, value in manifest.items():
                if 'usesCleartextTraffic' in str(key) or 'Cleartext' in str(value):
                    features.has_cleartext_traffic = True
                if 'certificatePinning' in str(key) or 'pinning' in str(key):
                    if 'bypass' in str(value).lower() or 'disabled' in str(value).lower():
                        features.has_cert_pinning_bypass = True
                if 'trust' in str(key).lower() and 'user' in str(value).lower():
                    features.trusts_user_ca = True
        elif isinstance(manifest, list):
            for item in manifest:
                if isinstance(item, dict):
                    title = str(item.get('title', '')).lower()
                    desc = str(item.get('description', '')).lower()
                    if 'cleartext' in title or 'cleartext' in desc:
                        features.has_cleartext_traffic = True
                    if 'pinning' in title or 'pinning' in desc:
                        features.has_cert_pinning_bypass = True

        sast = report_data.get('sast_findings', {})
        if isinstance(sast, dict):
            all_findings = sast.get('high', []) + sast.get('medium', []) + sast.get('low', [])
            for f in all_findings:
                if isinstance(f, dict):
                    title = str(f.get('title', '')).lower()
                    if 'cleartext' in title:
                        features.has_cleartext_traffic = True
                    if 'trust' in title and 'user' in title:
                        features.trusts_user_ca = True

        return features

    def _extract_components(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract exported components and total component counts"""
        exp_comp = report_data.get('exported_components', {})
        if isinstance(exp_comp, dict):
            features.exported_activities = exp_comp.get('activities', 0) or 0
            features.exported_services = exp_comp.get('services', 0) or 0
            features.exported_receivers = exp_comp.get('receivers', 0) or 0
            features.exported_providers = exp_comp.get('providers', 0) or 0

        exported_count = report_data.get('exported_count', {})
        if isinstance(exported_count, dict):
            features.exported_activities = max(features.exported_activities, exported_count.get('exported_activities', 0) or 0)
            features.exported_services = max(features.exported_services, exported_count.get('exported_services', 0) or 0)
            features.exported_receivers = max(features.exported_receivers, exported_count.get('exported_receivers', 0) or 0)
            features.exported_providers = max(features.exported_providers, exported_count.get('exported_providers', 0) or 0)

        for key, feat_attr in [
            ('exported_activities', 'exported_activities'),
            ('exported_services', 'exported_services'),
            ('exported_receivers', 'exported_receivers'),
            ('exported_providers', 'exported_providers')
        ]:
            val = report_data.get(key)
            if isinstance(val, list):
                setattr(features, feat_attr, max(getattr(features, feat_attr), len(val)))
            elif isinstance(val, int):
                setattr(features, feat_attr, max(getattr(features, feat_attr), val))

        activities = report_data.get('activities', [])
        services = report_data.get('services', [])
        receivers = report_data.get('receivers', [])
        providers = report_data.get('providers', [])

        features.total_activities = len(activities) if isinstance(activities, list) else 0
        features.total_services = len(services) if isinstance(services, list) else 0
        features.total_receivers = len(receivers) if isinstance(receivers, list) else 0
        features.total_providers = len(providers) if isinstance(providers, list) else 0

        return features

    def _extract_malware(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract malware detection information"""
        vt = report_data.get('virus_total', {})
        if isinstance(vt, dict):
            features.vt_positives = vt.get('positives', 0)
            features.vt_total = vt.get('total', 0)
        
        malware_perms = report_data.get('malware_permissions', {})
        if isinstance(malware_perms, dict):
            top_perms = malware_perms.get('top_malware_permissions', [])
            features.malware_permissions = top_perms
        
        return features

    def _extract_certificate(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract certificate information"""
        cert_analysis = report_data.get('certificate_analysis', {})
        if isinstance(cert_analysis, dict):
            cert_findings = cert_analysis.get('certificate_findings', [])
            if isinstance(cert_findings, list):
                for finding in cert_findings:
                    if isinstance(finding, list) and len(finding) > 1:
                        if str(finding[0]).lower() in ['high', 'critical']:
                            features.cert_issues += 1
            
            if 'validity_not_after' in cert_analysis:
                try:
                    not_after = datetime.strptime(cert_analysis['validity_not_after'], '%Y-%m-%d %H:%M:%S')
                    features.cert_validity_days = (not_after - datetime.now()).days
                    if features.cert_validity_days < 0:
                        features.cert_expired = True
                except:
                    pass
        
        return features

    def _extract_secrets_and_flags(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract hardcoded secrets and manifest flags"""
        secrets = report_data.get('hardcoded_secrets', [])
        if isinstance(secrets, list):
            features.hardcoded_secrets = list(secrets)

        sast = report_data.get('sast_findings', {})
        if isinstance(sast, dict):
            all_findings = sast.get('high', []) + sast.get('medium', []) + sast.get('low', [])
            for f in all_findings:
                if isinstance(f, dict):
                    title = str(f.get('title', '')).lower()
                    rule_id = str(f.get('rule_id', '')).lower()
                    if 'secret' in title or 'api_key' in rule_id or 'password' in title:
                        features.hardcoded_secrets.append(f.get('title', 'Secret found'))

        manifest = report_data.get('manifest_analysis', {})
        if isinstance(manifest, dict):
            for key, value in manifest.items():
                if isinstance(value, dict):
                    if 'debuggable' in str(key).lower():
                        features.is_debuggable = True
                    if 'backup' in str(key).lower():
                        features.has_backup = True
                    if 'secure' in str(key).lower() or 'FLAG_SECURE' in str(value):
                        features.has_secure_flag = True
        elif isinstance(manifest, list):
            for item in manifest:
                if isinstance(item, dict):
                    title = str(item.get('title', '')).lower()
                    if 'debuggable' in title:
                        features.is_debuggable = True
                    if 'backup' in title:
                        features.has_backup = True
                    if 'flag_secure' in title:
                        features.has_secure_flag = True

        return features

    def _extract_trackers(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract tracker information"""
        trackers = report_data.get('tracker_analysis', {})
        if isinstance(trackers, dict):
            features.trackers = trackers.get('trackers', [])
        return features

    def _extract_dangerous_apis(self, features: RiskFeatures, report_data: Dict) -> RiskFeatures:
        """Extract dangerous API calls"""
        dangerous_apis = [
            'Runtime.exec', 'ProcessBuilder',
            'DexClassLoader', 'PathClassLoader',
            'loadUrl', 'webview',
            'getExternalStorage', 'openFileOutput',
            'sendTextMessage', 'sendMultimediaMessage',
            'startActivity', 'startService'
        ]
        
        code_analysis = report_data.get('code_analysis', {})
        if isinstance(code_analysis, dict):
            for key, value in code_analysis.items():
                if isinstance(value, dict):
                    for api in dangerous_apis:
                        if api in str(key) or api in str(value):
                            features.dangerous_apis.append(key)
                            break
        
        files = report_data.get('files', [])
        if isinstance(files, list):
            features.native_libs = sum(1 for f in files if isinstance(f, str) and '.so' in f)
        
        return features

    def _calculate_risk_scores(self, features: RiskFeatures) -> Dict[str, float]:
        """Calculate independent risk scores with corrected values"""
        
        severity_score = min(100, 
            (features.high_findings * 25) +
            (features.medium_findings * 10) +
            (features.low_findings * 3)
        )
        
        perm_score = min(60, len(features.dangerous_perms) * 4)
        patterns, combo_weight = self.permission_detector.analyze(features.dangerous_perms)
        combo_score = min(60, combo_weight * 2) if patterns else 0
        permission_score = min(100, perm_score + combo_score)
        
        apkid_score = 0
        if features.has_packer:
            packer_weights = self.APKID_WEIGHTS['packer']
            if features.packer_name:
                for packer, weight in packer_weights.items():
                    if packer.lower() in features.packer_name.lower():
                        apkid_score += weight
                        break
                else:
                    apkid_score += packer_weights['default']
            else:
                apkid_score += 15
        
        if features.has_anti_vm:
            apkid_score += 20
        if features.has_anti_debug:
            apkid_score += 20
        if features.has_anti_hook:
            apkid_score += 15
        if features.has_reflection:
            apkid_score += 12
        if features.has_obfuscation:
            apkid_score += 10
        
        apkid_score = min(100, apkid_score)
        
        malware_score = 0
        if features.vt_positives > 0:
            malware_score = min(100, int(25 * math.log(features.vt_positives + 1) * 3.5))
        
        if features.malware_permissions:
            malware_score += min(30, len(features.malware_permissions) * 3)
        
        malware_score = min(100, malware_score)
        
        network_score = 0
        if features.has_cleartext_traffic:
            network_score += 20
        if features.has_cert_pinning_bypass:
            network_score += 25
        if features.trusts_user_ca:
            network_score += 15
        network_score = min(100, network_score)
        
        total_exported = (features.exported_activities + features.exported_services + 
                         features.exported_receivers + features.exported_providers)
        component_score = min(100, total_exported * 5)
        
        cert_score = 0
        if features.cert_issues > 0:
            cert_score += features.cert_issues * 15
        if features.cert_expired:
            cert_score += 40
        elif features.cert_validity_days < 30 and features.cert_validity_days > 0:
            cert_score += 25
        elif features.cert_validity_days < 90:
            cert_score += 15
        cert_score = min(100, cert_score)
        
        secrets_score = min(100, len(features.hardcoded_secrets) * 15)
        
        manifest_score = 0
        if features.is_debuggable:
            manifest_score += 20
        if features.has_backup:
            manifest_score += 15
        if not features.has_secure_flag:
            manifest_score += 10
        manifest_score = min(100, manifest_score)
        
        return {
            'severity_findings': severity_score,
            'permissions': permission_score,
            'apkid_analysis': apkid_score,
            'malware_detection': malware_score,
            'network_security': network_score,
            'exported_components': component_score,
            'certificate': cert_score,
            'hardcoded_secrets': secrets_score,
            'manifest_flags': manifest_score
        }

    def _compute_final_risk(self, risk_scores: Dict[str, float]) -> int:
        """
        Compute final risk score using corrected feature weights.
        Now properly weights malware detection and certificate issues.
        """
        final_score = (
            risk_scores['severity_findings'] * self.FEATURE_WEIGHTS['high_findings'] +
            risk_scores['permissions'] * self.FEATURE_WEIGHTS['permission_combinations'] +
            risk_scores['apkid_analysis'] * self.FEATURE_WEIGHTS['apkid_malware'] +
            risk_scores['malware_detection'] * self.FEATURE_WEIGHTS['malware_detection'] +
            risk_scores['network_security'] * self.FEATURE_WEIGHTS['network_security'] +
            risk_scores['exported_components'] * self.FEATURE_WEIGHTS['exported_components'] +
            risk_scores['certificate'] * self.FEATURE_WEIGHTS['certificate'] +
            risk_scores['hardcoded_secrets'] * self.FEATURE_WEIGHTS['secrets'] +
            risk_scores['manifest_flags'] * self.FEATURE_WEIGHTS['manifest_flags']
        )
        
        min_score = 0
        if risk_scores['malware_detection'] > 0:
            min_score = max(min_score, 40)
        if risk_scores['certificate'] > 30:
            min_score = max(min_score, 25)
        if risk_scores['apkid_analysis'] > 50:
            min_score = max(min_score, 35)
        
        return max(min_score, min(100, int(final_score)))

    def _classify_risk(self, final_score: int, risk_scores: Dict[str, float]) -> Dict[str, Any]:
        """Classify risk with better thresholds"""
        
        if final_score >= 75:
            risk_level = "Critical Risk"
        elif final_score >= 60:
            risk_level = "High Risk"
        elif final_score >= 40:
            risk_level = "Medium Risk"
        elif final_score >= 20:
            risk_level = "Low Risk"
        else:
            risk_level = "Minimal Risk"
        
        if risk_scores['malware_detection'] >= 60:
            risk_level = "High Risk - Malware Detected"
        elif risk_scores['malware_detection'] >= 40:
            risk_level = "Medium Risk - Suspicious Signatures"
        
        if risk_scores['certificate'] >= 70:
            risk_level = f"{risk_level} (Certificate Compromised)"
        elif risk_scores['certificate'] >= 50:
            risk_level = f"{risk_level} (Certificate Issues)"
        
        if risk_scores['apkid_analysis'] >= 70:
            risk_level = f"{risk_level} (Heavy Obfuscation)"
        
        flags = []
        if final_score >= 75:
            flags.append("🚨 CRITICAL: Immediate action required")
        
        if risk_scores['malware_detection'] >= 60:
            flags.append(f"🛡️ HIGH MALWARE RISK: {risk_scores['malware_detection']:.1f}%")
        elif risk_scores['malware_detection'] >= 40:
            flags.append(f"⚠️ Malware signatures detected: {risk_scores['malware_detection']:.1f}%")
        
        if risk_scores['severity_findings'] >= 60:
            flags.append(f"⚠️ High severity findings: {risk_scores['severity_findings']:.1f}%")
        
        if risk_scores['permissions'] >= 50:
            flags.append("🔑 Dangerous permission combination detected")
        
        if risk_scores['apkid_analysis'] >= 50:
            flags.append("🕵️ Anti-analysis techniques detected")
        
        if risk_scores['network_security'] >= 50:
            flags.append("🌐 Network security vulnerabilities")
        
        if risk_scores['exported_components'] >= 40:
            flags.append("🔓 Excessive exported components")
        
        if risk_scores['hardcoded_secrets'] >= 30:
            flags.append("🔑 Hardcoded secrets found")
        
        if risk_scores['certificate'] >= 50:
            flags.append(f"🔐 Certificate issues: {risk_scores['certificate']:.1f}%")
        
        remediation = []
        
        if risk_scores['malware_detection'] >= 40:
            remediation.append({
                'priority': 'P0',
                'action': 'IMMEDIATE MALWARE INVESTIGATION',
                'details': f'VirusTotal detections: {risk_scores["malware_detection"]:.1f}% - This app may contain malware!'
            })
        
        if risk_scores['severity_findings'] >= 50:
            remediation.append({
                'priority': 'P0',
                'action': 'Fix high-severity findings',
                'details': f'Severity score: {risk_scores["severity_findings"]:.1f}%'
            })
        
        if risk_scores['certificate'] >= 50:
            remediation.append({
                'priority': 'P1',
                'action': 'Fix certificate issues',
                'details': f'Certificate score: {risk_scores["certificate"]:.1f}% - Review and renew certificate'
            })
        
        if risk_scores['permissions'] >= 50:
            remediation.append({
                'priority': 'P1',
                'action': 'Review dangerous permission combinations',
                'details': 'Malicious permission patterns detected'
            })
        
        if risk_scores['apkid_analysis'] >= 50:
            remediation.append({
                'priority': 'P2',
                'action': 'Investigate anti-analysis techniques',
                'details': 'Packers, obfuscation, or anti-debug detected'
            })
        
        if risk_scores['network_security'] >= 40:
            remediation.append({
                'priority': 'P1',
                'action': 'Fix network security issues',
                'details': 'Cleartext traffic or certificate issues detected'
            })
        
        if risk_scores['hardcoded_secrets'] >= 30:
            remediation.append({
                'priority': 'P0',
                'action': 'Remove hardcoded secrets',
                'details': 'API keys, passwords, or tokens found in code'
            })
        
        return {
            'risk_level': risk_level,
            'flags': flags,
            'remediation': remediation
        }

    def _build_response(self, report_data: Dict, features: RiskFeatures, 
                       risk_scores: Dict[str, float], final_risk: int, 
                       classification: Dict[str, Any], pdf_path: Optional[str] = None, 
                       pdf_base64: Optional[str] = None) -> Dict[str, Any]:
        """Build standardized response"""
        legacy_flags = []
        if features.H > 0:
            legacy_flags.append(f"Found {features.H} High severity findings.")
        if features.M > 0:
            legacy_flags.append(f"Found {features.M} Medium severity findings.")
        if features.DP > 0:
            legacy_flags.append(f"Found {features.DP} Dangerous permissions.")
        if features.EC > 0:
            legacy_flags.append(f"Found {features.EC} Exported Components.")
        if features.AV > 0:
            legacy_flags.append("Anti-VM tactics detected.")
        if features.AD > 0:
            legacy_flags.append("Anti-Debug tactics detected.")
        if features.OB > 0:
            legacy_flags.append("Code Obfuscation detected.")
        if features.PK > 0:
            legacy_flags.append("Packer detected.")
        if features.CT > 0:
            legacy_flags.append("Cleartext traffic is enabled.")
        if features.CI > 0:
            legacy_flags.append(f"Found {features.CI} Certificate issues.")
        if features.MS > 0:
            legacy_flags.append(f"VirusTotal detected {features.MS} malware signatures.")
        
        return {
            "status": "Success",
            "message": "Analysis Complete!",
            "pdf_report_url": f"/reports/{os.path.basename(pdf_path)}" if pdf_path else None,
            "pdf_base64": pdf_base64,
            "analysis_verdict": classification['risk_level'],
            "threat_score": final_risk,
            "threat_flags": legacy_flags + classification['flags'],
            "risk_breakdown": risk_scores,
            "remediation_suggestions": classification['remediation'],
            "feature_summary": {
                "severity_findings": {
                    "high": features.H,
                    "medium": features.M,
                    "low": features.low_findings
                },
                "permissions": {
                    "dangerous_count": features.DP,
                    "combinations_found": len(features.permission_combinations)
                },
                "apkid": {
                    "has_packer": features.has_packer,
                    "packer_name": features.packer_name,
                    "anti_vm": features.has_anti_vm,
                    "anti_debug": features.has_anti_debug,
                    "anti_hook": features.has_anti_hook,
                    "obfuscation": features.has_obfuscation
                },
                "malware": {
                    "vt_positives": features.MS,
                    "vt_total": features.vt_total
                },
                "network": {
                    "cleartext_traffic": features.has_cleartext_traffic,
                    "cert_pinning_bypass": features.has_cert_pinning_bypass
                },
                "components": {
                    "exported_activities": features.exported_activities,
                    "exported_services": features.exported_services,
                    "exported_receivers": features.exported_receivers,
                    "exported_providers": features.exported_providers,
                    "total_activities": getattr(features, 'total_activities', 0),
                    "total_services": getattr(features, 'total_services', 0),
                    "total_receivers": getattr(features, 'total_receivers', 0),
                    "total_providers": getattr(features, 'total_providers', 0),
                    "total": features.EC
                },
                "certificate": {
                    "issues": features.CI,
                    "expired": features.cert_expired,
                    "validity_days": features.cert_validity_days
                },
                "secrets": {
                    "count": len(features.hardcoded_secrets)
                },
                "trackers": {
                    "count": len(features.trackers)
                }
            },
            "mobsf_summary": {
                "app_name": report_data.get("app_name") or report_data.get("file_name", "N/A"),
                "package_name": report_data.get("package_name", "N/A"),
                "version": report_data.get("version_name") or report_data.get("version", "1.0"),
                "security_score": report_data.get("security_score", 0),
                "min_sdk": report_data.get("min_sdk", "N/A"),
                "target_sdk": report_data.get("target_sdk", "N/A"),
                "file_count": report_data.get("file_count", 0),
                "size": report_data.get("size", 0)
            },
            "permissions": report_data.get("permissions", []),
            "sast_findings": report_data.get("sast_findings", {})
        }


    def _upload_file(self, file_path: str) -> Dict:
        """Upload file to MobSF — timeout 60s"""
        headers = {'Authorization': self.MOBSF_API_KEY}
        upload_url = f"{self.MOBSF_URL}/api/v1/upload"
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            upload_res = requests.post(upload_url, headers=headers, files=files, timeout=60)
            
        if upload_res.status_code != 200:
            return {"error": f"MobSF Upload Failed: {upload_res.text}"}
        return upload_res.json()

    def _trigger_scan(self, hash_val: str, scan_type: str) -> Dict:
        """Trigger MobSF scan — timeout 300s (large APKs can take a few minutes)"""
        headers = {'Authorization': self.MOBSF_API_KEY}
        scan_url = f"{self.MOBSF_URL}/api/v1/scan"
        scan_res = requests.post(scan_url, headers=headers,
                               data={'hash': hash_val, 'scan_type': scan_type},
                               timeout=300)
        
        if scan_res.status_code != 200:
            return {"error": f"MobSF Scan Failed: {scan_res.text}"}
        return scan_res.json()

    def _get_report(self, hash_val: str) -> Dict:
        """Get JSON report — timeout 60s"""
        headers = {'Authorization': self.MOBSF_API_KEY}
        report_url = f"{self.MOBSF_URL}/api/v1/report_json"
        report_res = requests.post(report_url, headers=headers,
                                 data={'hash': hash_val},
                                 timeout=60)
        
        if report_res.status_code != 200:
            return {"error": f"Report fetch failed: {report_res.text}"}
        return report_res.json()

    def _download_pdf_with_base64(self, hash_val: str) -> Tuple[Optional[str], Optional[str]]:
        """Download PDF report from official MobSF Docker container (with retry logic)"""
        headers = {'Authorization': self.MOBSF_API_KEY}
        pdf_url = f"{self.MOBSF_URL}/api/v1/download_pdf"
        
        import time
        for attempt in range(3):
            try:
                pdf_res = requests.post(pdf_url, headers=headers,
                                      data={'hash': hash_val}, stream=True, timeout=60)
                if pdf_res.status_code == 200 and (b'%PDF' in pdf_res.content[:20]):
                    os.makedirs("reports", exist_ok=True)
                    pdf_filename = f"{hash_val}_mobsf_report.pdf"
                    pdf_path = os.path.abspath(f"reports/{pdf_filename}")
                    
                    with open(pdf_path, 'wb') as f:
                        f.write(pdf_res.content)
                    
                    pdf_base64 = base64.b64encode(pdf_res.content).decode('utf-8')
                    return pdf_path, pdf_base64
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as ex:
                print(f"MobSF Docker PDF download attempt {attempt + 1} note: {ex}")
            time.sleep(2)
        
        return None, None

    def _generate_local_pdf(self, hash_val: str, report_data: Dict, features: RiskFeatures,
                            risk_scores: Dict[str, float], final_risk: int, 
                            classification: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Generates an official-styled MobSF PDF forensic report using ReportLab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            os.makedirs("reports", exist_ok=True)
            pdf_filename = f"{hash_val}_mobsf_report.pdf"
            pdf_path = os.path.abspath(f"reports/{pdf_filename}")

            doc = SimpleDocTemplate(pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                'TitleStyle', parent=styles['Heading1'], fontSize=18, leading=22,
                textColor=colors.HexColor("#0f172a")
            )
            subtitle_style = ParagraphStyle(
                'SubTitleStyle', parent=styles['Normal'], fontSize=9, leading=13,
                textColor=colors.HexColor("#64748b")
            )
            h2_style = ParagraphStyle(
                'H2Style', parent=styles['Heading2'], fontSize=11, leading=15,
                textColor=colors.HexColor("#1e293b"), spaceBefore=10, spaceAfter=6
            )
            body_style = ParagraphStyle(
                'BodyStyle', parent=styles['Normal'], fontSize=8.5, leading=12,
                textColor=colors.HexColor("#334155")
            )
            flag_style = ParagraphStyle(
                'FlagStyle', parent=styles['Normal'], fontSize=8.5, leading=12,
                textColor=colors.HexColor("#991b1b")
            )

            elements = []

            # Title Header
            elements.append(Paragraph("<b>CYBERX FORENSICS — MOBSF STATIC ANALYSIS REPORT</b>", title_style))
            elements.append(Paragraph(f"OWASP Mobile Security Framework Analysis • Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
            elements.append(Spacer(1, 8))
            elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=12))

            # Metadata Table
            app_name = report_data.get("app_name") or report_data.get("file_name", "N/A")
            pkg_name = report_data.get("package_name", "N/A")
            version = report_data.get("version_name") or report_data.get("version", "1.0")
            sdk = f"Min: API {report_data.get('min_sdk', 'N/A')} | Target: API {report_data.get('target_sdk', 'N/A')}"

            meta_data = [
                [Paragraph("<b>App Name</b>", body_style), Paragraph(str(app_name), body_style)],
                [Paragraph("<b>Package Name</b>", body_style), Paragraph(str(pkg_name), body_style)],
                [Paragraph("<b>Version</b>", body_style), Paragraph(str(version), body_style)],
                [Paragraph("<b>SDK Target / Min</b>", body_style), Paragraph(sdk, body_style)],
                [Paragraph("<b>SHA-256 Hash</b>", body_style), Paragraph(str(hash_val), body_style)],
            ]
            t_meta = Table(meta_data, colWidths=[140, 400])
            t_meta.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(t_meta)
            elements.append(Spacer(1, 12))

            # Threat Verdict Banner
            verdict = classification.get('risk_level', 'Unknown Risk')
            bg_col = colors.HexColor("#fee2e2") if final_risk >= 60 else (colors.HexColor("#fef3c7") if final_risk >= 30 else colors.HexColor("#dcfce7"))
            txt_col = colors.HexColor("#991b1b") if final_risk >= 60 else (colors.HexColor("#92400e") if final_risk >= 30 else colors.HexColor("#166534"))

            banner_data = [[
                Paragraph(f"<b>VERDICT: {verdict.upper()}</b>", ParagraphStyle('B1', parent=body_style, fontSize=11, textColor=txt_col, alignment=1)),
                Paragraph(f"<b>THREAT SCORE: {final_risk} / 100</b>", ParagraphStyle('B2', parent=body_style, fontSize=11, textColor=txt_col, alignment=1))
            ]]
            t_banner = Table(banner_data, colWidths=[300, 240])
            t_banner.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), bg_col),
                ('BOX', (0,0), (-1,-1), 1, txt_col),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            elements.append(t_banner)
            elements.append(Spacer(1, 12))

            # Risk Dimension Breakdown Table
            elements.append(Paragraph("<b>RISK DIMENSION ANALYSIS</b>", h2_style))
            rows = [[Paragraph("<b>Risk Category</b>", body_style), Paragraph("<b>Score (%)</b>", body_style), Paragraph("<b>Status</b>", body_style)]]
            for cat, sc in risk_scores.items():
                cat_title = cat.replace('_', ' ').title()
                st = "CRITICAL" if sc >= 75 else ("HIGH" if sc >= 50 else ("MEDIUM" if sc >= 25 else "LOW"))
                rows.append([Paragraph(cat_title, body_style), Paragraph(f"{sc:.1f}%", body_style), Paragraph(st, body_style)])

            t_breakdown = Table(rows, colWidths=[220, 160, 160])
            t_breakdown.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(t_breakdown)
            elements.append(Spacer(1, 12))

            # Threat Flags
            flags = classification.get('flags', [])
            if flags:
                elements.append(Paragraph("<b>DETECTED THREAT FLAGS & ANOMALIES</b>", h2_style))
                for flg in flags:
                    elements.append(Paragraph(f"• {flg}", flag_style))
                elements.append(Spacer(1, 10))

            # Remediation Suggestions
            remediations = classification.get('remediation', [])
            if remediations:
                elements.append(Paragraph("<b>SECURITY REMEDIATION PLAN</b>", h2_style))
                rem_rows = [[Paragraph("<b>Priority</b>", body_style), Paragraph("<b>Action Item</b>", body_style), Paragraph("<b>Details</b>", body_style)]]
                for r in remediations:
                    rem_rows.append([
                        Paragraph(f"<b>{r.get('priority', 'P1')}</b>", body_style),
                        Paragraph(r.get('action', ''), body_style),
                        Paragraph(r.get('details', ''), body_style)
                    ])
                t_rem = Table(rem_rows, colWidths=[50, 180, 310])
                t_rem.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                    ('PADDING', (0,0), (-1,-1), 4),
                ]))
                elements.append(t_rem)

            doc.build(elements)

            with open(pdf_path, 'rb') as f:
                pdf_b64 = base64.b64encode(f.read()).decode('utf-8')
            return pdf_path, pdf_b64
        except Exception as ex:
            print(f"Local MobSF PDF generator error: {ex}")
            return None, None


    def run_dynamic_analysis(self, file_path: str, wait_time: int = 30) -> Dict:
        """Uploads APK, starts dynamic analysis, waits, stops it, and gets report."""
        if not os.path.exists(file_path):
            return {"error": f"APK file not found: {file_path}"}
            
        if self.MOBSF_API_KEY == "YOUR_MOBSF_API_KEY":
            return {"error": "MobSF API key not configured"}
            
        try:
            try:
                requests.get(self.MOBSF_URL, timeout=5)
            except requests.exceptions.ConnectionError:
                return {"error": f"Cannot connect to MobSF at {self.MOBSF_URL}. Is MobSF running?"}
            except requests.exceptions.Timeout:
                return {"error": f"MobSF at {self.MOBSF_URL} is not responding (timeout). Is it running?"}

            upload_data = self._upload_file(file_path)
            if 'error' in upload_data:
                return upload_data
                
            hash_val = upload_data.get("hash")
            
            headers = {'Authorization': self.MOBSF_API_KEY}
            
            start_url = f"{self.MOBSF_URL}/api/v1/dynamic/start_analysis"
            start_res = requests.post(start_url, headers=headers, data={'hash': hash_val}, timeout=60)
            if start_res.status_code != 200:
                return {"error": f"Failed to start dynamic analysis: {start_res.text}"}
                
            import time
            time.sleep(wait_time)
            
            stop_url = f"{self.MOBSF_URL}/api/v1/dynamic/stop_analysis"
            stop_res = requests.post(stop_url, headers=headers, data={'hash': hash_val}, timeout=60)
            if stop_res.status_code != 200:
                return {"error": f"Failed to stop dynamic analysis: {stop_res.text}"}
                
            report_url = f"{self.MOBSF_URL}/api/v1/dynamic/report_json"
            report_res = requests.post(report_url, headers=headers, data={'hash': hash_val}, timeout=60)
            if report_res.status_code != 200:
                return {"error": f"Failed to fetch dynamic report: {report_res.text}"}
                
            return report_res.json()
            
        except requests.exceptions.ConnectionError:
            return {"error": f"Cannot connect to MobSF at {self.MOBSF_URL}."}
        except requests.exceptions.Timeout:
            return {"error": "MobSF request timed out."}
        except Exception as e:
            return {"error": str(e)}


_analyzer = MobSFAnalyzer()

def run_mobsf_scan(file_path: str) -> Dict:
    """
    Main entry point for Static Analysis
    """
    return _analyzer.run_mobsf_scan(file_path)

def run_mobsf_dynamic_scan(file_path: str, wait_time: int = 30) -> Dict:
    """
    Main entry point for Dynamic Analysis
    """
    return _analyzer.run_dynamic_analysis(file_path, wait_time)