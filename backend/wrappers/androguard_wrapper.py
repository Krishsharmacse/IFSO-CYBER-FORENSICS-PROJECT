import os
import logging
from androguard.core.apk import APK

# Suppress spammy warnings from androguard about malformed APKs
logging.getLogger("androguard").setLevel(logging.ERROR)
try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

def analyze_apk(file_path: str):
    """
    Uses Androguard to statically analyze an APK file, extract metadata, 
    and automatically calculate a basic threat score based on rules.
    """
    if not os.path.exists(file_path):
        return {"error": f"APK file not found: {file_path}"}
        
    try:
        apk = APK(file_path)
        
        app_name = apk.get_app_name() or ""
        package = apk.get_package() or ""
        permissions = apk.get_permissions() or []
        services = apk.get_services() or []
        
        # --- Automated Threat Analysis ---
        threat_score = 0
        threat_flags = []
        
        # 1. Check Impersonation
        app_name_lower = app_name.lower()
        if "whatsapp" in app_name_lower and package != "com.whatsapp" and package != "com.whatsapp.w4b":
            threat_score += 100
            threat_flags.append(f"FAKE APP DETECTED: Claims to be WhatsApp but package is '{package}'")
            
        if "instagram" in app_name_lower and package != "com.instagram.android":
            threat_score += 100
            threat_flags.append(f"FAKE APP DETECTED: Claims to be Instagram but package is '{package}'")
            
        if "facebook" in app_name_lower and package != "com.facebook.katana":
            threat_score += 100
            threat_flags.append(f"FAKE APP DETECTED: Claims to be Facebook but package is '{package}'")

        # 2. Check Suspicious Permissions
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
            threat_score += 30
            threat_flags.append("Has permission to draw over other apps (High risk of overlay malware)")
            
        if "android.permission.SEND_SMS" in permissions:
            threat_score += 20
            threat_flags.append("Can silently send SMS messages (Risk of premium SMS fraud)")
            
        if "android.permission.READ_SMS" in permissions:
            threat_score += 20
            threat_flags.append("Can read your SMS messages (Risk of OTP stealing)")
            
        if "android.permission.READ_CONTACTS" in permissions:
            threat_score += 10
            threat_flags.append("Can read all your contacts (Privacy risk)")
            
        if "android.permission.RECORD_AUDIO" in permissions and "android.permission.CAMERA" in permissions:
            threat_score += 15
            threat_flags.append("Has full access to both Microphone and Camera (Spyware risk)")

        # 3. Check for Suspicious Third-Party Tracking / Ad Networks
        all_perms_str = " ".join(permissions).lower()
        all_services_str = " ".join(services).lower()
        
        if "applovin" in all_perms_str or "applovin" in all_services_str:
            threat_score += 10
            threat_flags.append("Contains AppLovin Advertising Network")
            
        if "appmetrica" in all_services_str:
            threat_score += 20
            threat_flags.append("Contains Yandex AppMetrica tracking service")
            
        # Determine Verdict
        verdict = "SAFE"
        if threat_score > 80:
            verdict = "MALICIOUS"
        elif threat_score > 30:
            verdict = "SUSPICIOUS"
                
        results = {
            "analysis_verdict": verdict,
            "threat_score": threat_score,
            "threat_flags": threat_flags,
            "app_name": app_name,
            "package": package,
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "permissions": permissions,
            "main_activity": apk.get_main_activity(),
            "activities": apk.get_activities(), 
            "services": services,
            "receivers": apk.get_receivers()
        }
        return results
    except Exception as e:
        return {"error": f"Androguard failed to parse APK: {str(e)}"}
