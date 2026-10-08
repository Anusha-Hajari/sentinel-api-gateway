import os
import sys
import time
import joblib
import numpy as np

# Ensure ml_engine is in import path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_engine"))
from features import extract_numerical_features, calculate_entropy, SQL_KEYWORDS, XSS_KEYWORDS, CMD_KEYWORDS, PATH_TRAVERSAL


class ThreatDetector:
    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_dir = os.path.join(base_dir, "ml_engine", "saved_models")

        clf_path = os.path.join(model_dir, "payload_classifier.joblib")
        anom_path = os.path.join(model_dir, "anomaly_detector.joblib")

        print("[*] Loading CSIC 2010 trained AI models into memory...")
        self.classifier = joblib.load(clf_path)
        self.anomaly_detector = joblib.load(anom_path)
        print("[+] Threat Detector Engine online and ready!")

    def _categorize_attack(self, text: str) -> str:
        """Determines the specific attack subtype based on token signatures."""
        if SQL_KEYWORDS.search(text) or "--" in text or "/*" in text:
            return "SQL Injection (SQLi)"
        if XSS_KEYWORDS.search(text) or "<" in text:
            return "Cross-Site Scripting (XSS)"
        if CMD_KEYWORDS.search(text) or PATH_TRAVERSAL.search(text):
            return "Command Injection / Traversal"
        return "CSIC Anomalous Attack"

    def analyze(self, target_text: str) -> dict:
        t0 = time.perf_counter()
        if not target_text or len(target_text.strip()) == 0:
            return {
                "is_threat": False,
                "threat_type": "Benign",
                "confidence": 1.0,
                "latency_ms": 0.0,
                "entropy": 0.0
            }

        # 1. Supervised CSIC 2010 Model Prediction
        probs = self.classifier.predict_proba([target_text])[0]
        # class 0 = Benign, class 1 = Anomalous Attack
        attack_prob = float(probs[1]) if len(probs) > 1 else 0.0
        
        # 2. Unsupervised Anomaly Detection
        features = extract_numerical_features(target_text)
        anom_pred = self.anomaly_detector.predict([features])[0]
        anom_score = float(self.anomaly_detector.score_samples([features])[0])
        entropy = calculate_entropy(target_text)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        
        # Legitimate alphanumeric user inputs (e.g. search queries, names, emails)
        # should not be blocked unless actual attack tokens or severe anomalies exist
        has_attack_signature = bool(
            SQL_KEYWORDS.search(target_text) or 
            XSS_KEYWORDS.search(target_text) or 
            CMD_KEYWORDS.search(target_text) or 
            PATH_TRAVERSAL.search(target_text) or
            any(char in target_text for char in ["'", '"', "<", ">", ";", "--", "/*", "../"])
        )

        # A threat requires high ML model probability AND either suspicious characters or high entropy
        is_threat = (attack_prob >= 0.75 and has_attack_signature) or (anom_pred == -1 and entropy > 4.5 and has_attack_signature)

        threat_type = "Benign"
        confidence = float(probs[0]) if not is_threat else attack_prob

        if is_threat:
            threat_type = self._categorize_attack(target_text)

        return {
            "is_threat": bool(is_threat),
            "threat_type": threat_type,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anom_score, 4),
            "entropy": entropy,
            "latency_ms": elapsed_ms
        }


# Initialize singleton instance
detector = ThreatDetector()