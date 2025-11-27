import pandas as pd
import re
import numpy as np
from urllib.parse import urlparse

def entropy(text):
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in prob)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    full = url.lower()

    # NOTE: The names here MUST match the column names used in the CSV for prediction consistency.
    features = {
        # 1. URLLength (CSV Name) <-> url_length (Concept)
        "URLLength": len(url), 
        
        # 2. NoOfDegitsInURL (CSV Name) <-> digit_count (Concept)
        "NoOfDegitsInURL": sum(c.isdigit() for c in full),
        
        # 3. NoOfLettersInURL (CSV Name) <-> letter_count (Concept)
        "NoOfLettersInURL": sum(c.isalpha() for c in full),

        # 4. NoOfQMarkInURL (CSV Name) <-> question_count (Concept)
        "NoOfQMarkInURL": full.count('?'),

        # 5. NoOfEqualsInURL (CSV Name) <-> equal_count (Concept)
        "NoOfEqualsInURL": full.count('='),

        # 6. IsDomainIP (CSV Name) <-> is_ip (Concept)
        "IsDomainIP": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        
        # 7. IsHTTPS (CSV Name) <-> https_flag (Concept)
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }

    # Ensure the features are returned in the exact order as defined in SELECTED_FEATURE_COLUMNS
    # By using the CSV column names as keys, we ensure the correct mapping.
    return pd.DataFrame([features])
