import time
import re
from typing import Dict, List, Optional, Tuple
from fastapi import Request

# Pre-defined test users and simulated JWT tokens
USER_TOKENS: Dict[str, str] = {
    "token_alice": "alice",
    "token_bob": "bob",
}

# Resource Ownership Registry
RESOURCE_OWNERSHIP: Dict[str, Dict[str, str]] = {
    # order_id -> owner
    "orders": {
        "101": "alice",
        "102": "alice",
        "201": "bob",
        "202": "bob",
    },
    # document_id -> owner
    "documents": {
        "doc_alice": "alice",
        "doc_bob": "bob",
    }
}

# Regex to detect resource access patterns (e.g., /api/orders/101 or /api/documents/doc_bob)
RESOURCE_PATH_REGEX = re.compile(r"^/api/(orders|documents)/([a-zA-Z0-9_\-]+)")


class BolaDetector:
    def __init__(self):
        # Sliding-window memory to track sequential enumeration:
        # client_ip -> list of (timestamp, resource_id)
        self.access_history: Dict[str, List[Tuple[float, str]]] = {}

    def extract_identity(self, request: Request) -> Optional[str]:
        """Extracts and verifies authenticated user from Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ", 1)[1].strip()
            return USER_TOKENS.get(token)
        return None

    def extract_resource(self, path: str) -> Optional[Tuple[str, str]]:
        """Extracts resource type and object ID from the request URI."""
        match = RESOURCE_PATH_REGEX.match(path)
        if match:
            return match.group(1), match.group(2)  # (resource_type, object_id)
        return None

    def check_behavioral_enumeration(self, client_key: str, object_id: str) -> bool:
        """
        Detects IDOR Enumeration / Scraping:
        Flags if a client probes >= 4 distinct object IDs within 10 seconds.
        """
        now = time.time()
        if client_key not in self.access_history:
            self.access_history[client_key] = []

        # Retain records from the last 15 seconds
        self.access_history[client_key] = [
            (t, oid) for (t, oid) in self.access_history[client_key] if now - t < 15
        ]
        self.access_history[client_key].append((now, object_id))

        distinct_ids = {oid for _, oid in self.access_history[client_key]}
        return len(distinct_ids) >= 4

    def inspect(self, request: Request) -> Dict:
        """
        Main BOLA / IDOR Inspection Logic:
        1. Checks direct object ownership.
        2. Evaluates behavioral enumeration / fuzzing.
        """
        path = request.url.path
        resource = self.extract_resource(path)

        if not resource:
            return {"is_threat": False, "threat_type": None, "confidence": 0.0}

        res_type, object_id = resource
        client_user = self.extract_identity(request)
        client_ip = request.client.host if request.client else "unknown"
        tracking_key = client_user or client_ip

        # 1. Behavioral Enumeration Check
        is_enumerating = self.check_behavioral_enumeration(tracking_key, object_id)
        if is_enumerating:
            return {
                "is_threat": True,
                "threat_type": "IDOR Object Enumeration",
                "confidence": 0.95,
                "detail": f"Sequential object enumeration detected on {res_type}"
            }

        # 2. Ownership Check (BOLA)
        type_ownership = RESOURCE_OWNERSHIP.get(res_type, {})
        actual_owner = type_ownership.get(object_id)

        # If resource exists and user is unauthorized
        if actual_owner:
            if not client_user:
                return {
                    "is_threat": True,
                    "threat_type": "BOLA / IDOR Violation",
                    "confidence": 1.0,
                    "detail": f"Unauthenticated access to protected {res_type}/{object_id}"
                }
            if client_user != actual_owner:
                return {
                    "is_threat": True,
                    "threat_type": "BOLA / IDOR Violation",
                    "confidence": 1.0,
                    "detail": f"User '{client_user}' attempted unauthorized access to '{actual_owner}'s {res_type} ({object_id})"
                }

        return {"is_threat": False, "threat_type": None, "confidence": 0.0}


# Singleton instance
bola_detector = BolaDetector()