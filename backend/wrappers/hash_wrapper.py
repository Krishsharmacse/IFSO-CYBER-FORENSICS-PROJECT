import os
import hashlib
import tempfile
import re
import time
import threading
from typing import Dict, List, Any, Tuple, Set
from wrappers.platform_utils import run, JOHN_BIN, IS_WINDOWS

# ============================================================================
# EXTENDED PASSWORD DICTIONARY
# ============================================================================

COMMON_PASSWORDS = [
    # Top common passwords
    "password", "123456", "12345678", "password123", "admin", "welcome", "login",
    "123456789", "secret", "pass", "12345", "1234567", "1234567890", "abc123",
    "p@ssword", "administrator", "root", "user", "guest", "master", "super",
    "cyber", "security", "shadow", "hacker", "dragon", "baseball", "football",
    "monkey", "letmein", "sunshine", "princess", "charlie", "trustno1", "system",
    "qwerty", "qwerty123", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "password!",
    "admin123", "welcome123", "letmein123", "monkey123", "password1",
    # Extended common passwords
    "iloveyou", "1234", "123123", "myspace1", "michael", "jennifer", "thomas",
    "jordan", "hunter", "amanda", "jessica", "joshua", "andrew", "nicole",
    "daniel", "cookie", "michelle", "summer", "freedom", "whatever", "batman",
    "access", "hello", "love", "soccer", "test", "buster", "george", "maggie",
    "pepper", "ginger", "tigger", "111111", "000000", "666666", "7777777",
    "121212", "654321", "123321", "passw0rd", "mustang", "master123", "killer",
    "matrix", "ranger", "computer", "starwars", "robert", "thunder", "taylor",
    "harley", "diamond", "silver", "golfer", "hammer", "corvette", "dallas",
    "cheese", "yankees", "sparky", "internet", "yellow", "orange", "purple",
    "chicken", "flower", "joseph", "angels", "friends", "coffee", "guitar",
    "phoenix", "butterfly", "amanda", "wizard", "samantha", "jackson", "ashley",
    "1234567891", "qwertyuiop", "asdfghjkl", "zxcvbnm", "pa55word", "p@55w0rd",
    "changeme", "default", "temp", "temp123", "test123", "backup",
]

# Add extended variations
EXTENDED_WORDS = []
for pwd in COMMON_PASSWORDS:
    EXTENDED_WORDS.append(pwd)
    EXTENDED_WORDS.append(pwd + "123")
    EXTENDED_WORDS.append(pwd + "!")
    EXTENDED_WORDS.append(pwd.capitalize())
    if pwd.isalpha():
        EXTENDED_WORDS.append(pwd + "2024")

COMMON_PASSWORDS = list(set(EXTENDED_WORDS))  # Remove duplicates

# ============================================================================
# PRE-COMPUTED HASH LOOKUP
# ============================================================================

PRECOMPUTED_HASHES: Dict[str, tuple] = {}
for word in COMMON_PASSWORDS:
    word_bytes = word.encode('utf-8')
    PRECOMPUTED_HASHES[hashlib.md5(word_bytes).hexdigest()] = (word, "MD5")
    PRECOMPUTED_HASHES[hashlib.sha1(word_bytes).hexdigest()] = (word, "SHA-1")
    PRECOMPUTED_HASHES[hashlib.sha256(word_bytes).hexdigest()] = (word, "SHA-256")
    PRECOMPUTED_HASHES[hashlib.sha384(word_bytes).hexdigest()] = (word, "SHA-384")
    PRECOMPUTED_HASHES[hashlib.sha512(word_bytes).hexdigest()] = (word, "SHA-512")

# ============================================================================
# HASH DETECTION
# ============================================================================

def detect_hash_type(hash_str: str) -> Tuple[str, str]:
    """
    Detect hash type and return (algorithm, john_format)
    
    Args:
        hash_str: Hash string to analyze
        
    Returns:
        Tuple of (algorithm_name, john_format_flag)
    """
    hash_str = hash_str.strip()
    
    # Check for crypt formats
    if hash_str.startswith('$2a$') or hash_str.startswith('$2b$') or hash_str.startswith('$2y$'):
        return "bcrypt", "bcrypt"
    if hash_str.startswith('$1$'):
        return "MD5 (crypt)", "md5crypt"
    if hash_str.startswith('$5$'):
        return "SHA-256 (crypt)", "sha256crypt"
    if hash_str.startswith('$6$'):
        return "SHA-512 (crypt)", "sha512crypt"
    if hash_str.startswith('$apr1$'):
        return "Apache MD5", "apr1"
    
    # Check for NTLM (uppercase hex)
    if len(hash_str) == 32 and re.match(r'^[0-9A-F]{32}$', hash_str):
        return "NTLM", "nt"
    
    # Standard hex hashes
    hash_lower = hash_str.lower()
    if not re.match(r'^[a-f0-9]+$', hash_lower):
        return "Unknown", None
    
    length = len(hash_lower)
    formats = {
        32: ("MD5", "raw-md5"),
        40: ("SHA-1", "raw-sha1"),
        64: ("SHA-256", "raw-sha256"),
        96: ("SHA-384", "raw-sha384"),
        128: ("SHA-512", "raw-sha512"),
    }
    
    if length in formats:
        return formats[length]
    
    return "Unknown", None

def detect_primary_algorithm(hashes: List[str]) -> Tuple[str, Set[str]]:
    """
    Detect the most common algorithm from a list of hashes
    
    Args:
        hashes: List of hash strings
        
    Returns:
        Tuple of (primary_algorithm, detected_algorithms)
    """
    algo_counts = {}
    for h in hashes:
        algo, _ = detect_hash_type(h)
        if algo != "Unknown":
            algo_counts[algo] = algo_counts.get(algo, 0) + 1
    
    if not algo_counts:
        return "Unknown", set()
    
    primary = max(algo_counts, key=algo_counts.get)
    return primary, set(algo_counts.keys())

# ============================================================================
# PROGRESS TRACKING
# ============================================================================

class ProgressTracker:
    """Track and report cracking progress"""
    
    def __init__(self, total: int, update_interval: int = 5):
        self.total = total
        self.interval = update_interval
        self.cracked = 0
        self.running = False
        self.start_time = None
    
    def start(self):
        self.running = True
        self.start_time = time.time()
        threading.Thread(target=self._track, daemon=True).start()
    
    def stop(self):
        self.running = False
    
    def update(self, count: int):
        self.cracked = count
    
    def _track(self):
        while self.running:
            time.sleep(self.interval)
            elapsed = time.time() - self.start_time
            rate = self.cracked / elapsed if elapsed > 0 else 0
            progress = (self.cracked / self.total * 100) if self.total > 0 else 0
            print(f"Progress: {self.cracked}/{self.total} ({progress:.1f}%) - {rate:.1f} hashes/sec")

# ============================================================================
# MAIN CRACKING FUNCTION
# ============================================================================

def crack_hash(file_path: str, jtr_timeout: int = 300, use_john: bool = False) -> Dict[str, Any]:
    """
    Cracks MD5, SHA-1, SHA-256, SHA-384, and SHA-512 hashes 
    using John the Ripper with a high-speed Python fallback.
    
    Args:
        file_path: Path to the text file containing hashes.
        jtr_timeout: Max execution time for John the Ripper per hash type (default: 5 minutes).
        use_john: Whether to use John the Ripper (default: True).
    
    Returns:
        Dictionary with cracking results and statistics.
    """
    if not os.path.exists(file_path):
        return {"error": f"Hash file not found: {file_path}"}

    cracked_results = []
    logs = []
    total_hashes = 0
    all_hashes = set()  # Track unique hashes
    
    # Group uncracked hashes by type for JtR
    # Using sets for O(1) removal
    uncracked_by_type = {}
    
    try:
        # Read and process each hash
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                h = line.strip()
                if not h or h.startswith('#'):
                    continue
                
                total_hashes += 1
                h_clean = h.lower()
                
                # Check if we've already seen this hash
                if h_clean in all_hashes:
                    continue
                all_hashes.add(h_clean)
                
                # O(1) lookup against precomputed hashes
                if h_clean in PRECOMPUTED_HASHES:
                    plaintext, algo = PRECOMPUTED_HASHES[h_clean]
                    cracked_results.append({
                        "hash": h_clean,
                        "plaintext": plaintext,
                        "algorithm": algo
                    })
                else:
                    # Detect hash type for JtR
                    algo, format_flag = detect_hash_type(h_clean)
                    if algo != "Unknown" and format_flag:
                        if algo not in uncracked_by_type:
                            uncracked_by_type[algo] = {
                                "format": format_flag,
                                "hashes": set()
                            }
                        uncracked_by_type[algo]["hashes"].add(h_clean)
                    else:
                        # Unknown format
                        if "Unknown" not in uncracked_by_type:
                            uncracked_by_type["Unknown"] = {
                                "format": None,
                                "hashes": set()
                            }
                        uncracked_by_type["Unknown"]["hashes"].add(h_clean)

        if total_hashes == 0:
            return {"error": "Hash file is empty or contains only invalid data."}

        python_cracked = len(cracked_results)
        logs.append(f"Python Fast Crack recovered {python_cracked}/{total_hashes} hashes instantly.")
        
        # Progress tracker
        tracker = ProgressTracker(total_hashes, update_interval=5)
        tracker.start()
        tracker.update(python_cracked)

        # JtR execution grouped by type
        if use_john and JOHN_BIN:
            for algo, data in uncracked_by_type.items():
                if not data["hashes"] or data["format"] is None:
                    continue
                
                if algo == "Unknown":
                    logs.append(f"Skipping {len(data['hashes'])} hashes with unknown format")
                    continue
                
                logs.append(f"Running John the Ripper on {len(data['hashes'])} {algo} hashes...")
                
                # Create isolated pot file
                pot_fd, pot_path = tempfile.mkstemp(suffix=".pot")
                os.close(pot_fd)  # Close fd immediately to avoid Windows file locking
                
                try:
                    # Write hashes to temp file in chunks
                    hash_list = list(data["hashes"])
                    temp_fd, temp_path = tempfile.mkstemp(suffix=".txt")
                    
                    try:
                        with os.fdopen(temp_fd, 'w', encoding='utf-8') as tf:
                            tf.write("\n".join(hash_list))
                        
                        # Run JtR with format and custom pot file
                        cmd = [
                            JOHN_BIN,
                            f"--format={data['format']}",
                            f"--pot={pot_path}",
                            temp_path
                        ]
                        
                        try:
                            run(cmd, timeout=jtr_timeout)
                        except Exception as e:
                            logs.append(f"JtR execution interrupted for {algo}: {str(e)}")
                        
                        # Extract results from our pot file
                        if os.path.exists(pot_path):
                            with open(pot_path, 'r', encoding='utf-8', errors='ignore') as pot_file:
                                for line in pot_file:
                                    if ':' in line:
                                        parts = line.strip().split(':', 1)
                                        if len(parts) >= 2:
                                            h = parts[0].strip().lower()
                                            p = parts[1].strip()
                                            
                                            # Verify the hash
                                            if h in data["hashes"]:
                                                data["hashes"].discard(h)
                                                cracked_results.append({
                                                    "hash": h,
                                                    "plaintext": p,
                                                    "algorithm": algo
                                                })
                                                tracker.update(len(cracked_results))
                                    
                    finally:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        
                finally:
                    if os.path.exists(pot_path):
                        os.remove(pot_path)

        tracker.stop()

        # Compile final uncracked list
        final_uncracked = []
        for data in uncracked_by_type.values():
            final_uncracked.extend(data["hashes"])

        cracked_cnt = len(cracked_results)
        recovery_rate = round((cracked_cnt / total_hashes) * 100, 1) if total_hashes > 0 else 0.0

        logs.append(f"Cracking complete: {cracked_cnt}/{total_hashes} hashes recovered ({recovery_rate}% success rate).")

        # Detect primary algorithm
        primary_algo, detected_algos = detect_primary_algorithm(all_hashes)

        return {
            "status": "Success",
            "total_hashes": total_hashes,
            "cracked_count": cracked_cnt,
            "recovery_rate": recovery_rate,
            "detected_type": primary_algo,
            "detected_algorithms": list(detected_algos),
            "cracked_passwords": cracked_results,
            "uncracked_hashes": final_uncracked[:1000],  # Limit to avoid huge response
            "uncracked_count": len(final_uncracked),
            "crack_log": logs,
            "statistics": {
                "python_cracked": python_cracked,
                "john_cracked": cracked_cnt - python_cracked,
                "dictionary_size": len(COMMON_PASSWORDS),
                "lookup_size": len(PRECOMPUTED_HASHES)
            }
        }

    except Exception as e:
        return {"error": f"Hash Cracking Failed: {str(e)}"}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def batch_crack_hashes(hashes: List[str], **kwargs) -> Dict[str, Any]:
    """
    Crack a list of hashes directly (without file I/O)
    
    Args:
        hashes: List of hash strings to crack
        **kwargs: Additional arguments for crack_hash
        
    Returns:
        Dictionary with cracking results
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(hashes))
        temp_path = f.name
    
    try:
        return crack_hash(temp_path, **kwargs)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def crack_hash_with_dict(file_path: str, custom_dict: List[str], **kwargs) -> Dict[str, Any]:
    """
    Crack hashes with a custom dictionary in addition to the built-in one
    
    Args:
        file_path: Path to hash file
        custom_dict: List of custom passwords to try
        **kwargs: Additional arguments for crack_hash
        
    Returns:
        Dictionary with cracking results
    """
    # Extend the global lookup (temporary)
    global PRECOMPUTED_HASHES
    
    original_lookup = PRECOMPUTED_HASHES.copy()
    
    try:
        for word in custom_dict:
            word_bytes = word.encode('utf-8')
            PRECOMPUTED_HASHES[hashlib.md5(word_bytes).hexdigest()] = (word, "MD5")
            PRECOMPUTED_HASHES[hashlib.sha1(word_bytes).hexdigest()] = (word, "SHA-1")
            PRECOMPUTED_HASHES[hashlib.sha256(word_bytes).hexdigest()] = (word, "SHA-256")
        
        return crack_hash(file_path, **kwargs)
    finally:
        # Restore original lookup
        PRECOMPUTED_HASHES = original_lookup

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Hash Cracker")
    parser.add_argument("-f", "--file", required=True, help="Path to hash file")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="JtR timeout in seconds")
    parser.add_argument("--no-john", action="store_true", help="Disable John the Ripper")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    result = crack_hash(args.file, jtr_timeout=args.timeout, use_john=not args.no_john)
    
    if "error" in result:
        print(f"❌ Error: {result['error']}")
    else:
        print(f"\n{'='*60}")
        print(f"✅ CRACKING RESULTS")
        print(f"{'='*60}")
        print(f"Total Hashes: {result['total_hashes']}")
        print(f"Cracked: {result['cracked_count']}")
        print(f"Success Rate: {result['recovery_rate']}%")
        print(f"Detected Type: {result['detected_type']}")
        print(f"Detected Algorithms: {', '.join(result['detected_algorithms'])}")
        print(f"\nStatistics:")
        print(f"  Python Cracker: {result['statistics']['python_cracked']}")
        print(f"  John the Ripper: {result['statistics']['john_cracked']}")
        print(f"  Dictionary Size: {result['statistics']['dictionary_size']}")
        print(f"  Lookup Table Size: {result['statistics']['lookup_size']}")
        
        if result['cracked_passwords']:
            print(f"\nFirst 10 Cracked Passwords:")
            for i, item in enumerate(result['cracked_passwords'][:10], 1):
                print(f"  {i}. {item['hash']} -> {item['plaintext']} ({item['algorithm']})")
        
        if result['crack_log'] and args.verbose:
            print(f"\nLogs:")
            for log in result['crack_log']:
                print(f"  {log}")
        
        print(f"{'='*60}\n")
