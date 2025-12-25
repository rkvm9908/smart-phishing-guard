import pandas as pd
import re
import math
from collections import Counter
from urllib.parse import urlparse
import tldextract 

SENSITIVE_WORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking', 
    'confirm', 'signin', 'bank', 'ebayisapi', 'webscr', 'password', 
    'credential', 'paypal', 'amazon', 'netflix', 'microsoft', 'office'
]

SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 
    'ow.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 
    'bitly.com', 'cur.lv', 'tiny.cc', 'ovh.to', 'su.pr', 'flic.kr'
]

SUSPICIOUS_TLDS = ['site', 'xyz', 'top', 'online', 'live', 'club', 'icu', 'vip', 'link', 'info', 'tk']

# --- Helper Function for Typosquatting (Entropy) ---
def get_entropy(text):
    if not text: return 0
    probs = [n/len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    hostname = parsed.netloc.lower()
    full_url_lower = url.lower()
    path = parsed.path
    query = parsed.query
    domain_only = ext.domain.lower()
    tld_only = ext.suffix.lower()

    features = {}

    # --- Basic Features ---
    features["URLLength"] = len(url)
    features["HostnameLength"] = len(hostname)
    features["PathLength"] = len(path)
    features["QueryLength"] = len(query)
    
    # --- Character Counts ---
    features["NoOfDigits"] = sum(c.isdigit() for c in full_url_lower)
    features["NoOfLetters"] = sum(c.isalpha() for c in full_url_lower)
    features["NoOfDots"] = full_url_lower.count('.')
    features["NoOfHyphens"] = full_url_lower.count('-')
    features["NoOfUnderscore"] = full_url_lower.count('_')
    features["NoOfSlash"] = full_url_lower.count('/')
    features["NoOfQuestionMark"] = full_url_lower.count('?')
    features["NoOfEqual"] = full_url_lower.count('=')
    features["NoOfAt"] = full_url_lower.count('@')
    features["NoOfAmpersand"] = full_url_lower.count('&')
    features["NoOfExclamation"] = full_url_lower.count('!')
    features["NoOfHash"] = full_url_lower.count('#')
    features["NoOfPercent"] = full_url_lower.count('%')
    features["NoOfTilde"] = full_url_lower.count('~')
    features["NoOfComma"] = full_url_lower.count(',')
    features["NoOfPlus"] = full_url_lower.count('+')
    features["NoOfAsterisk"] = full_url_lower.count('*')
    features["NoOfDollar"] = full_url_lower.count('$')
    features["NoOfSpace"] = full_url_lower.count(' ') + full_url_lower.count('%20')
    
    features["NoOfSubdomains"] = max(0, hostname.count('.') - 1)
    features["NoOfSubDir"] = path.count('/')
    
    # --- Structural Checks ---
    features["IsDomainIP"] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    features["IsHTTPS"] = 1 if parsed.scheme == "https" else 0
    features["IsWWW"] = 1 if hostname.startswith("www.") else 0
    features["IsShortened"] = 1 if any(service in hostname for service in SHORTENING_SERVICES) else 0
    features["HasSensitiveWord"] = 1 if any(word in full_url_lower for word in SENSITIVE_WORDS) else 0
    
    try:
        features["HasPort"] = 1 if parsed.port else 0
    except ValueError:
        features["HasPort"] = 0
        
    features["AbnormalDoubleSlash"] = 1 if url.find("//", 7) != -1 else 0
    features["DomainDigitCount"] = sum(c.isdigit() for c in domain_only)
    features["DomainDigitRatio"] = features["DomainDigitCount"] / len(domain_only) if len(domain_only) > 0 else 0
    features["IsSuspiciousTLD"] = 1 if tld_only in SUSPICIOUS_TLDS else 0
    features["RedirectInURL"] = 1 if url.lower().count("http") > 1 or url.count("//") > 1 else 0
    features["NoOfUppercase"] = sum(1 for c in url if c.isupper())
    features["UppercaseRatio"] = features["NoOfUppercase"] / len(url) if len(url) > 0 else 0
    features["DigitRatio"] = features["NoOfDigits"] / len(url) if len(url) > 0 else 0
    features["LetterRatio"] = features["NoOfLetters"] / len(url) if len(url) > 0 else 0
    features["SymbolCount"] = sum(1 for c in full_url_lower if not c.isalnum())
    features["SymbolRatio"] = features["SymbolCount"] / len(url) if len(url) > 0 else 0

    # --- ADVANCED POWER FEATURES (Typosquatting & Homograph Fix) ---
    # 1. Entropy: Detects random/jumbled characters used in Typosquatting
    features["URLEntropy"] = get_entropy(url)
    
    # 2. Punycode/Non-ASCII Check: Detects Homograph (Fake characters like Cyrillic 'a')
    # If the URL contains 'xn--' or any non-standard character, it's flagged.
    features["IsPunycode"] = 1 if "xn--" in url.lower() or any(ord(c) > 127 for c in url) else 0

    # --- CRITICAL FIX FOR FEATURE ORDER ---
    df = pd.DataFrame([features])
    df = df[SELECTED_FEATURE_COLUMNS] 
    
    return df

SELECTED_FEATURE_COLUMNS = [
    "URLLength", "HostnameLength", "PathLength", "QueryLength", "NoOfDigits", 
    "NoOfLetters", "NoOfDots", "NoOfHyphens", "NoOfUnderscore", "NoOfSlash", 
    "NoOfQuestionMark", "NoOfEqual", "NoOfAt", "NoOfAmpersand", "NoOfExclamation", 
    "NoOfHash", "NoOfPercent", "NoOfTilde", "NoOfComma", "NoOfPlus", "NoOfAsterisk", 
    "NoOfDollar", "NoOfSpace", "NoOfSubdomains", "NoOfSubDir", "IsDomainIP", 
    "IsHTTPS", "IsWWW", "IsShortened", "HasSensitiveWord", "HasPort", 
    "AbnormalDoubleSlash", "DigitRatio", "LetterRatio", "SymbolCount", "SymbolRatio", 
    "DomainDigitCount", "DomainDigitRatio", "IsSuspiciousTLD", "RedirectInURL", 
    "NoOfUppercase", "UppercaseRatio", 
    "URLEntropy", "IsPunycode"  
]
