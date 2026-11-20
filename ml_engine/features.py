import math
import re
from typing import Dict
import numpy as np

# Malicious token patterns
SQL_KEYWORDS = re.compile(
    r'\b(select|union|insert|update|delete|drop|truncate|alter|exec|declare|cast|benchmark|sleep)\b',
    re.IGNORECASE
)
XSS_KEYWORDS = re.compile(
    r'(<script|javascript:|onload=|onerror=|onclick=|<svg|<iframe|<img|<body|<input)',
    re.IGNORECASE
)
CMD_KEYWORDS = re.compile(
    r'(\bcat\b|\bls\b|\bwhoami\b|\bnetsh\b|\bpwd\b|/etc/passwd|win\.ini|/bin/sh|/bin/bash)',
    re.IGNORECASE
)
PATH_TRAVERSAL = re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE)

SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~")


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of an incoming HTTP string.
    Formula: H = - sum(p * log2(p))
    High entropy indicates encoded, compressed, or heavily obfuscated payloads.
    """
    if not text:
        return 0.0

    prob_dict: Dict[str, int] = {}
    length = len(text)
    
    # Step 1: Count frequency of each character
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1

    # Step 2: Apply Shannon Entropy Formula
    entropy = 0.0
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def extract_numerical_features(payload: str) -> np.ndarray:
    """
    Extracts 9 numerical security features from raw payload:
    [length, entropy, special_char_ratio, digit_ratio, upper_ratio, 
     sql_hits, xss_hits, cmd_hits, path_hits]
    """
    if not isinstance(payload, str):
        payload = str(payload)

    length = len(payload)
    if length == 0:
        return np.zeros(9, dtype=np.float32)

    # 1. Statistical features
    entropy = calculate_entropy(payload)
    special_count = sum(1 for c in payload if c in SPECIAL_CHARS)
    digit_count = sum(1 for c in payload if c.isdigit())
    upper_count = sum(1 for c in payload if c.isupper())

    special_ratio = special_count / length
    digit_ratio = digit_count / length
    upper_ratio = upper_count / length

    # 2. Threat signature hit counts
    sql_hits = len(SQL_KEYWORDS.findall(payload))
    xss_hits = len(XSS_KEYWORDS.findall(payload))
    cmd_hits = len(CMD_KEYWORDS.findall(payload))
    path_hits = len(PATH_TRAVERSAL.findall(payload))

    return np.array([
        float(length),
        float(entropy),
        float(special_ratio),
        float(digit_ratio),
        float(upper_ratio),
        float(sql_hits),
        float(xss_hits),
        float(cmd_hits),
        float(path_hits)
    ], dtype=np.float32)