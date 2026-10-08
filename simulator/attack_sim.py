import time
import random
import httpx

GATEWAY_URL = "http://127.0.0.1:8000"

# Realistic legitimate requests
BENIGN_TRAFFIC = [
    {"endpoint": "/api/products", "params": {"search": "wireless_headphones"}},
    {"endpoint": "/api/products", "params": {"search": "usb_c_hub_multiport"}},
    {"endpoint": "/api/products", "params": {"search": "mechanical_keyboard_rgb"}},
    {"endpoint": "/api/products", "params": {"search": "ergonomic_desk_mat"}},
    {"endpoint": "/api/products", "params": {"search": "dual_monitor_arm"}},
    {"endpoint": "/api/user/profile", "params": {"user_id": "10492"}},
    {"endpoint": "/api/products", "params": {"search": "webcam_1080p_60fps"}},
    {"endpoint": "/health", "params": {}},
]

# Realistic real-world attack vectors
MALICIOUS_TRAFFIC = [
    # SQL Injections
    {"endpoint": "/api/products", "params": {"search": "' OR '1'='1"}},
    {"endpoint": "/api/products", "params": {"search": "' UNION SELECT null, username, password FROM users --"}},
    {"endpoint": "/api/products", "params": {"search": "admin' --"}},
    {"endpoint": "/api/products", "params": {"search": "1; DROP TABLE products; --"}},
    {"endpoint": "/api/products", "params": {"search": "1' AND SLEEP(5) --"}},
    
    # Cross-Site Scripting (XSS)
    {"endpoint": "/api/products", "params": {"search": "<script>alert('XSS_ATTACK')</script>"}},
    {"endpoint": "/api/products", "params": {"search": "<img src=x onerror=alert(document.cookie)>"}},
    {"endpoint": "/api/products", "params": {"search": "<svg/onload=alert('PWNED')>"}},
    
    # Command Injection / Path Traversal
    {"endpoint": "/api/products", "params": {"search": "../../../../etc/passwd"}},
    {"endpoint": "/api/products", "params": {"search": "..\\..\\windows\\win.ini"}},
    {"endpoint": "/api/products", "params": {"search": "; cat /etc/shadow"}},
    {"endpoint": "/api/products", "params": {"search": "| whoami"}},
]


def run_live_simulation(total_requests: int = 30):
    print("=" * 65)
    print("      SENTINEL-API-GATEWAY: LIVE TRAFFIC & ATTACK SIMULATOR")
    print("=" * 65)
    print(f"[*] Target Gateway: {GATEWAY_URL}")
    print(f"[*] Simulating {total_requests} mixed traffic requests...")
    print("=" * 65)

    passed_count = 0
    blocked_count = 0

    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        for i in range(1, total_requests + 1):
            # 60% chance benign, 40% chance attack
            is_attack = random.random() < 0.4
            
            if is_attack:
                req = random.choice(MALICIOUS_TRAFFIC)
                label = "🚨 [ATTACK]"
            else:
                req = random.choice(BENIGN_TRAFFIC)
                label = "✅ [BENIGN]"

            try:
                t0 = time.perf_counter()
                res = client.get(req["endpoint"], params=req["params"])
                latency = round((time.perf_counter() - t0) * 1000, 2)

                if res.status_code == 200:
                    passed_count += 1
                    status_text = "200 ALLOWED"
                elif res.status_code == 403:
                    blocked_count += 1
                    data = res.json()
                    status_text = f"403 BLOCKED ({data.get('threat_type', 'Threat')})"
                else:
                    status_text = f"{res.status_code} OTHER"

                payload_display = list(req["params"].values())[0] if req["params"] else "none"
                print(f"[{i:02d}/{total_requests}] {label:10} {status_text:28} | Latency: {latency:5.1f}ms | Payload: {payload_display[:35]}")

            except Exception as e:
                print(f"[!] Error sending request: {e}")

            # Realistic human-like delay between requests (0.4 to 1.2 seconds)
            time.sleep(random.uniform(0.4, 1.2))

    print("\n" + "=" * 65)
    print("SIMULATION COMPLETED!")
    print(f"  Total Requests Sent : {total_requests}")
    print(f"  Allowed (Clean)     : {passed_count}")
    print(f"  Blocked (Threats)   : {blocked_count}")
    print("=" * 65)


if __name__ == "__main__":
    run_live_simulation(total_requests=25)