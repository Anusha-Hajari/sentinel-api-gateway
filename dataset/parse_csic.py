import os
import re
import pandas as pd


def parse_csic_file(file_path: str, label: int, category: str) -> list:
    print(f"[*] Parsing: {os.path.basename(file_path)} ...")
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Split requests by standard HTTP separator (double newline before next request)
    raw_blocks = re.split(r'\n\n(?=(?:GET|POST|PUT|DELETE)\s)', content)

    records = []
    for block in raw_blocks:
        block = block.strip()
        if not block:
            continue

        lines = block.splitlines()
        first_line = lines[0].strip() if lines else ""
        parts = first_line.split()

        if len(parts) < 2:
            continue

        method = parts[0]
        uri = parts[1]

        # Extract POST body if present
        body = ""
        body_split = block.split("\n\n", 1)
        if len(body_split) > 1:
            body = body_split[1].strip()

        # Combine URI parameters and body for payload inspection
        full_payload = uri
        if body:
            full_payload += " " + body

        records.append({
            "method": method,
            "uri": uri,
            "body": body,
            "payload": full_payload,
            "label": label,
            "category": category
        })

    print(f"    [+] Extracted {len(records)} requests from {os.path.basename(file_path)}")
    return records


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    raw_dir = os.path.join(base_dir, "raw")

    train_normal_file = os.path.join(raw_dir, "normalTrafficTraining.txt")
    anomalous_file = os.path.join(raw_dir, "anomalousTrafficTest.txt")

    if not os.path.exists(train_normal_file) or not os.path.exists(anomalous_file):
        print(f"[!] Error: Could not find raw files in {raw_dir}")
        print("    Please ensure normalTrafficTraining.txt and anomalousTrafficTest.txt are in dataset/raw/")
        return

    print("=" * 65)
    print(" STAGE 2: PARSING RAW HTTP BENCHMARK INTO STRUCTURED DATASET")
    print("=" * 65)

    # 1. Parse Normal and Anomalous traffic
    normal_data = parse_csic_file(train_normal_file, label=0, category="benign")
    anom_data = parse_csic_file(anomalous_file, label=1, category="anomalous")

    # 2. Combine and shuffle
    combined = normal_data + anom_data
    df = pd.DataFrame(combined)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # 3. Save structured benchmark dataset
    out_csv = os.path.join(base_dir, "payloads.csv")
    df.to_csv(out_csv, index=False)

    print("\n" + "=" * 65)
    print(f"[+] Stage 2 Complete! Structured dataset generated at: {out_csv}")
    print(f"[+] Total HTTP Requests Parsed: {len(df)}")
    print(f"[+] Class Balance:\n{df['category'].value_counts()}")
    print("=" * 65)


if __name__ == "__main__":
    main()