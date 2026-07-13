import requests
import whois
import hashlib
import os
from wrappers import ml_phishing_wrapper

def check_phishing_heuristics(target: str) -> dict:
    suspicious_keywords = [
        "trycloudflare.com", "ngrok-free.app", "ngrok.io", "serveo.net",
        "loca.lt", "localhost.run", "portmap.io", "pinggy.link", "zrok.io",
        "bore.pub", "loophole.site", "localto.net"
    ]
    target_lower = target.lower()
    for kw in suspicious_keywords:
        if kw in target_lower:
            return {
                "is_suspicious": True,
                "reason": f"Target contains '{kw}' which is an ephemeral tunneling provider heavily abused by automated phishing frameworks (e.g., Zphisher).",
                "risk_level": "CRITICAL",
                "recommendation": "Block immediately. Highly likely to be a zero-day phishing link."
            }
    return {"is_suspicious": False}

def calculate_universal_risk(results):
    import datetime
    score = 0
    factors = []
    
    # 1. Local Heuristics
    lh = results.get("local_heuristics", {})
    if lh.get("is_suspicious"):
        score += 100
        factors.append(f"Local Heuristics flagged as HIGH RISK: {lh.get('reason')}")
        
    # 2. Google Safebrowsing
    gs = results.get("google_safebrowsing", {})
    if gs and not gs.get("is_safe", True):
        score += 35
        factors.append("Google Safebrowsing flagged site as dangerous/malicious.")
        
    # 3. ML Model
    ml = results.get("ml_analysis", {})
    if ml and ml.get("prediction") != "benign":
        ml_score = (ml.get("confidence", 0) / 100.0) * 35
        score += ml_score
        factors.append(f"AI Model predicts {ml.get('prediction').upper()} with {ml.get('confidence')}% confidence.")
        
    # 4. Pulsedive
    pd = results.get("pulsedive", {})
    if pd:
        risk = pd.get("risk", "none").lower()
        if risk in ["high", "critical"]:
            score += 30
            factors.append(f"Pulsedive Threat Intel reports {risk.upper()} risk.")
        elif risk == "medium":
            score += 15
            factors.append(f"Pulsedive Threat Intel reports {risk.upper()} risk.")
            
    # 5. WHOIS Domain Age
    whois_info = results.get("whois_info", {})
    if whois_info and whois_info.get("creation_date"):
        try:
            import re
            creation_str = str(whois_info.get("creation_date"))
            
            # Check for datetime.datetime(YYYY, MM, DD...) pattern
            dt_match = re.search(r'datetime\.datetime\((\d{4}),\s*(\d{1,2}),\s*(\d{1,2})', creation_str)
            # Check for standard YYYY-MM-DD pattern
            str_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', creation_str)
            
            creation_date = None
            if dt_match:
                creation_date = datetime.datetime(int(dt_match.group(1)), int(dt_match.group(2)), int(dt_match.group(3)))
            elif str_match:
                creation_date = datetime.datetime(int(str_match.group(1)), int(str_match.group(2)), int(str_match.group(3)))
                
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                if age_days < 180:
                    score += 15
                    factors.append(f"Domain is very young ({age_days} days old). Less than 6 months is highly suspicious.")
                else:
                    factors.append(f"Domain has an established age of {age_days} days.")
            else:
                factors.append("Domain creation date was empty or unparseable.")
        except Exception as e:
            factors.append(f"Could not parse domain creation date for age verification. ({e})")
            
    score = min(round(score), 100)
    
    verdict = "SAFE"
    if score >= 75:
        verdict = "CRITICAL"
    elif score >= 50:
        verdict = "HIGH"
    elif score >= 25:
        verdict = "MEDIUM"
        
    return {
        "risk_score": score,
        "verdict": verdict,
        "factors": factors
    }

def analyze_threat(target: str, scan_type: str, api_key: str = None):
    """
    Performs Threat Intelligence lookups based on scan_type.
    - ip: Free IP-API lookup
    - whois: Python-whois lookup
    - virustotal: VT File Hash Lookup (Requires API Key)
    - abuseipdb: AbuseIPDB IP lookup (Requires API Key)
    - shodan: Shodan Host lookup (Requires API Key)
    - malwarebazaar: MalwareBazaar Hash Lookup (Free, no API key required)
    - alienvault: AlienVault OTX Lookup (Requires API Key)
    - safebrowsing, urlscan, pulsedive: Free URL lookups
    """
    results = {}
    
    # Run local heuristics before external API checks for domain/URL targets
    if scan_type in ["whois", "safebrowsing", "urlscan", "pulsedive", "alienvault", "ml_url_analyzer", "universal_url_validator"]:
        heuristics = check_phishing_heuristics(target)
        if heuristics["is_suspicious"]:
            results["local_heuristics"] = heuristics

    try:
        if scan_type == "ip":
            # Free IP-API lookup
            res = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,as,org,lat,lon,reverse")
            if res.status_code == 200:
                results["ip_info"] = res.json()
            else:
                results["error"] = "Failed to fetch IP info"

        elif scan_type == "whois":
            # Python-whois lookup
            domain = whois.whois(target)
            results["whois_info"] = {
                "registrar": domain.registrar,
                "creation_date": str(domain.creation_date),
                "expiration_date": str(domain.expiration_date),
                "name_servers": domain.name_servers,
                "dnssec": domain.dnssec,
                "status": domain.status
            }
            
        elif scan_type == "virustotal":
            api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
            if not api_key:
                return {"error": "VirusTotal API key is required. Provide it in UI or .env"}
            
            # Target is expected to be a file path for VirusTotal
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
                
            # Hash the file to lookup
            sha256_hash = hashlib.sha256()
            with open(target, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            headers = {"x-apikey": api_key}
            res = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
            
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                results["virustotal"] = {
                    "hash": file_hash,
                    "malicious_hits": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "undetected_hits": data.get("last_analysis_stats", {}).get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "suggested_threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
                }
            elif res.status_code == 404:
                 results["virustotal"] = {"message": "File hash not found in VirusTotal database. Uploading full files via API requires additional setup."}
            else:
                 results["error"] = f"VirusTotal API Error: {res.text}"

        elif scan_type == "abuseipdb":
            api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
            if not api_key:
                return {"error": "AbuseIPDB API key is required. Provide it in UI or .env"}
            
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {
                'ipAddress': target,
                'maxAgeInDays': '90'
            }
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if res.status_code == 200:
                results["abuseipdb"] = res.json().get("data", {})
            else:
                results["error"] = f"AbuseIPDB API Error: {res.text}"
                
        elif scan_type == "shodan":
            api_key = api_key or os.getenv("SHODAN_API_KEY")
            if not api_key:
                return {"error": "Shodan API key is required. Provide it in UI or .env"}
                
            res = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
            if res.status_code == 200:
                data = res.json()
                results["shodan"] = {
                    "ip": data.get("ip_str"),
                    "organization": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", [])
                }
            elif res.status_code == 404:
                results["shodan"] = {"message": "No information available for that IP in Shodan."}
            else:
                results["error"] = f"Shodan API Error: {res.text}"

        elif scan_type == "malwarebazaar":
            api_key = api_key or os.getenv("MALWAREBAZAAR_API_KEY")
            if not api_key:
                return {"error": "MalwareBazaar API key is required. Provide it in UI or .env"}

            # Target is expected to be a file path for MalwareBazaar
            if not os.path.exists(target):
                return {"error": f"File not found: {target}"}
                
            sha256_hash = hashlib.sha256()
            with open(target, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            headers = {"Auth-Key": api_key}
            data = {'query': 'get_info', 'hash': file_hash}
            res = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
            if res.status_code == 200:
                mb_data = res.json()
                if mb_data.get("query_status") == "hash_not_found":
                    results["malwarebazaar"] = {"message": "File hash not found in MalwareBazaar database."}
                else:
                    results["malwarebazaar"] = mb_data
            else:
                results["error"] = f"MalwareBazaar API Error: {res.text}"

        elif scan_type == "alienvault":
            api_key = api_key or os.getenv("ALIENVAULT_API_KEY")
            if not api_key:
                return {"error": "AlienVault OTX API key is required. Provide it in UI or .env"}
            
            headers = {"X-OTX-API-KEY": api_key}
            
            import ipaddress
            try:
                ip = ipaddress.ip_address(target)
                indicator_type = "IPv4" if ip.version == 4 else "IPv6"
            except ValueError:
                indicator_type = "domain"
                
            res = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}/general", headers=headers)
            if res.status_code == 200:
                data = res.json()
                results["alienvault"] = {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                    "base_indicator": data.get("base_indicator", {})
                }
            elif res.status_code == 404:
                results["alienvault"] = {"message": "No pulse information available for that target in AlienVault OTX."}
            else:
                results["error"] = f"AlienVault API Error: {res.text}"

        elif scan_type == "ml_url_analyzer":
            results.update(ml_phishing_wrapper.analyze_url_ml(target))
            
        elif scan_type == "safebrowsing":
            # If target looks like a Google Transparency Report search link, extract the target URL
            if "transparencyreport.google.com/safe-browsing/search" in target:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(target)
                queries = parse_qs(parsed.query)
                if "url" in queries and len(queries["url"]) > 0:
                    target = queries["url"][0]

            # Google Transparency Report Safe Browsing lookup (no key required)
            url = f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={target}"
            res = requests.get(url)
            if res.status_code == 200:
                text = res.text
                if text.startswith(")]}'"):
                    text = text[4:].strip()
                
                try:
                    import json
                    raw_data = json.loads(text)
                    status_info = None
                    for item in raw_data:
                        if isinstance(item, list) and len(item) > 0 and item[0] == "sb.ssr":
                            status_info = item
                            break
                    
                    if status_info and len(status_info) >= 9:
                        status_code = status_info[1]
                        status_map = {
                            1: "Safe (No issues found)",
                            2: "Unsafe (Malicious or dangerous)",
                            3: "Partially Unsafe (Some pages are unsafe)",
                            5: "Uncommon Downloads (Contains potentially suspicious downloads)",
                            6: "No data (Not enough data or site is too new)"
                        }
                        status_str = status_map.get(status_code, f"Unknown Status ({status_code})")
                        
                        results["google_safebrowsing"] = {
                            "domain": status_info[8],
                            "status_code": status_code,
                            "status_description": status_str,
                            "is_safe": status_code == 1 or status_code == 6,
                            "redirects_to_harmful": status_info[2],
                            "installs_unwanted_software": status_info[3],
                            "is_phishing": status_info[4],
                            "contains_malware": status_info[5],
                            "uncommon_downloads": status_info[6],
                            "last_scanned_timestamp": status_info[7]
                        }
                    else:
                        results["error"] = "Invalid response format from Google Transparency Report API"
                except Exception as ex:
                    results["error"] = f"Failed to parse Transparency Report response: {str(ex)}"
            else:
                results["error"] = f"Google Transparency Report API returned status {res.status_code}"

        elif scan_type == "urlscan":
            from urllib.parse import urlparse
            domain = target
            if "://" in target:
                domain = urlparse(target).netloc
            elif "/" in target:
                domain = target.split("/")[0]
                
            res = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
            if res.status_code == 200:
                data = res.json()
                results["urlscan"] = {
                    "total_scans": data.get("total", 0),
                    "results": data.get("results", [])[:5]
                }
            else:
                results["error"] = f"URLScan API Error: {res.text}"

        elif scan_type == "pulsedive":
            res = requests.get(f"https://pulsedive.com/api/info.php?indicator={target}")
            if res.status_code == 200 or res.status_code == 404:
                try:
                    data = res.json()
                    if data.get("error") == "Indicator not found.":
                        results["pulsedive"] = {"message": "Target not found in Pulsedive database.", "risk": "unknown"}
                    elif "error" in data:
                        results["error"] = data["error"]
                    else:
                        results["pulsedive"] = {
                            "indicator": data.get("indicator"),
                            "risk": data.get("risk"),
                            "risk_recommended": data.get("risk_recommended"),
                            "threats": [t.get("name") for t in data.get("threats", [])],
                            "properties": data.get("properties", {})
                        }
                except Exception as ex:
                    results["error"] = f"Pulsedive JSON Parse Error: {str(ex)}"
            else:
                results["error"] = f"Pulsedive API Error: {res.text}"


        elif scan_type == "universal_url_validator":
            results.update(analyze_threat(target, "ml_url_analyzer", api_key))
            results.update(analyze_threat(target, "safebrowsing", api_key))
            results.update(analyze_threat(target, "urlscan", api_key))
            results.update(analyze_threat(target, "pulsedive", api_key))
            
            try:
                import urllib.parse
                clean_target = target
                if "://" in clean_target:
                    clean_target = urllib.parse.urlparse(clean_target).netloc
                results.update(analyze_threat(clean_target, "whois", api_key))
            except Exception as e:
                pass
                
            results["aggregated_risk_assessment"] = calculate_universal_risk(results)
            
            # Fix nested status from recursive calls
            results.pop("status", None)
            results.pop("error", None)

        else:
            results["error"] = f"Unknown scan type: {scan_type}"

        results["status"] = "Success" if "error" not in results else "Failed"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "Failed"
        
    return results

# Alias for main.py integration
run_intel_scan = analyze_threat

