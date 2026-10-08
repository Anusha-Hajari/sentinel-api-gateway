import sys
from sqlalchemy import create_engine, text

# Replace with your actual password
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/sentinel_db"

print("[*] Testing PostgreSQL connection...")
try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version();")).fetchone()
        print("[+] SUCCESS! Connected to PostgreSQL:")
        print(f"    {result[0]}")
except Exception as e:
    print(f"[!] Connection failed: {e}")