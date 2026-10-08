import math
import re
from typing import Dict, Any
import numpy as np

# Key security indicator patterns
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
    Calculates Shannon Entropy of a string.
    High entropy indicates encoded, compressed, or heavily obfuscated payloads.
    """
    if not text:
        return 0.0
    prob_dict: Dict[str, int] = {}
    length = len(text)
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_numerical_features(payload: str) -> np.ndarray:
    """
    Extracts numerical feature vector for Anomaly Detection (Isolation Forest):
    [length, entropy, special_char_ratio, digit_ratio, upper_ratio, 
     sql_hit_count, xss_hit_count, cmd_hit_count, path_traversal_count]
    """
    if not isinstance(payload, str):
        payload = str(payload)

    length = len(payload)
    if length == 0:
        return np.zeros(9, dtype=np.float32)

    entropy = calculate_entropy(payload)
    special_count = sum(1 for c in payload if c in SPECIAL_CHARS)
    digit_count = sum(1 for c in payload if c.isdigit())
    upper_count = sum(1 for c in payload if c.isupper())

    special_ratio = special_count / length
    digit_ratio = digit_count / length
    upper_ratio = upper_count / length

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