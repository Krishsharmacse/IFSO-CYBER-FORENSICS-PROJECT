import eml_parser
import json
import datetime
import os

def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()

def analyze_email(file_path: str):
    if not os.path.exists(file_path):
        return {"error": f"Email file not found: {file_path}"}
    try:
        ep = eml_parser.EmlParser(include_attachment_data=True, include_raw_body=True)
        parsed_eml = ep.decode_email(file_path)
        res_str = json.dumps(parsed_eml, default=json_serial)
        email_data = json.loads(res_str)

        # Advanced Cyber Analysis & Threat Scoring
        threat_flags = []
        threat_score = 0

        hdr = email_data.get('header', {})
        hdr_raw = hdr.get('header', {})

        # 1. Subject Analysis
        subject = hdr.get('subject', '')
        if not subject and hdr_raw.get('subject'):
            subject = hdr_raw.get('subject')[0] if isinstance(hdr_raw.get('subject'), list) else str(hdr_raw.get('subject'))
        
        urgent_keywords = ['urgent', 'limited', 'suspend', 'verify', 'action required', 'security alert', 'locked', 'unusual activity']
        if any(kw in subject.lower() for kw in urgent_keywords):
            threat_flags.append(f"Urgent/Coercive Subject: '{subject}' (creates panic/urgency)")
            threat_score += 25

        # 2. From & Display Name Analysis
        from_raw = hdr_raw.get('from', [''])[0] if isinstance(hdr_raw.get('from'), list) else str(hdr_raw.get('from', ''))
        from_email = hdr.get('from', '')
        
        # Check Brand Impersonation
        known_brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'bank', 'wellsfargo', 'chase']
        from_lower = from_raw.lower()
        for brand in known_brands:
            if brand in from_lower and brand not in from_email.lower():
                threat_flags.append(f"Brand Impersonation: Display name claims '{brand.upper()}' but email domain is '{from_email.split('@')[-1] if '@' in from_email else from_email}'")
                threat_score += 35
                break

        # 3. Reply-To Mismatch
        reply_to_list = hdr_raw.get('reply-to', [])
        reply_to = reply_to_list[0] if reply_to_list else ''
        if reply_to and from_email and reply_to.lower() != from_email.lower():
            if any(provider in reply_to.lower() for provider in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']):
                threat_flags.append(f"Critical Reply-To Mismatch: Corporate sender '{from_email}' directs replies to webmail '{reply_to}'")
                threat_score += 30
            else:
                threat_flags.append(f"Reply-To Mismatch: Replies directed to '{reply_to}' instead of sender '{from_email}'")
                threat_score += 20

        # 4. Originating IP
        received_ips = hdr.get('received_ip', [])
        originating_ip = received_ips[0] if received_ips else 'Unknown'
        if originating_ip.startswith('203.0.113.') or originating_ip.startswith('198.51.100.'):
            threat_flags.append(f"Reserved Documentation IP Range ({originating_ip}): Sample intentionally uses test range")
        
        # 5. Received Hops Path
        received_hops = hdr.get('received', [])

        # 6. Body Hashes, URIs, and Domains
        body_parts = email_data.get('body', [])
        uris = []
        domains = []
        uri_hashes = []
        domain_hashes = []
        body_hashes = []

        for b in body_parts:
            if 'uri' in b:
                uris.extend(b['uri'])
            if 'domain' in b:
                domains.extend(b['domain'])
            if 'uri_hash' in b:
                uri_hashes.extend(b['uri_hash'])
            if 'domain_hash' in b:
                domain_hashes.extend(b['domain_hash'])
            if 'hash' in b:
                body_hashes.append({'type': b.get('content_type', 'text/plain'), 'hash': b['hash']})

        # Add suspicious link flag if links found
        if uris:
            for u in set(uris):
                if any(kw in u.lower() for kw in ['login', 'verify', 'account', 'secure']):
                    threat_flags.append(f"Suspicious Action URL Found in Body: '{u}'")
                    threat_score += 15

        threat_score = min(100, threat_score)

        if threat_score >= 60:
            analysis_verdict = "MALICIOUS / HIGH RISK PHISHING"
        elif threat_score >= 30:
            analysis_verdict = "SUSPICIOUS EMAIL"
        else:
            analysis_verdict = "BENIGN / LOW RISK"

        return {
            "status": "Success",
            "analysis_verdict": analysis_verdict,
            "threat_score": threat_score,
            "threat_flags": threat_flags,
            "parsed_summary": {
                "subject": subject,
                "from_display": from_raw,
                "from_email": from_email,
                "reply_to": reply_to or "Same as From",
                "to": hdr.get('to', []),
                "date": hdr.get('date', ''),
                "message_id": hdr_raw.get('message-id', ['N/A'])[0] if isinstance(hdr_raw.get('message-id'), list) else 'N/A',
                "originating_ip": originating_ip,
                "total_hops": len(received_hops),
                "received_ips": received_ips,
                "received_domains": hdr.get('received_domain', []),
                "content_types": [b.get('content_type') for b in body_parts if 'content_type' in b],
                "extracted_uris": list(set(uris)),
                "extracted_domains": list(set(domains)),
                "uri_hashes": list(set(uri_hashes)),
                "domain_hashes": list(set(domain_hashes)),
                "body_hashes": body_hashes,
                "received_hops": received_hops
            },
            "email_data": email_data
        }
    except Exception as e:
        return {"error": str(e)}
