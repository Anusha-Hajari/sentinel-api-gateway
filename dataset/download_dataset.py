import os
import urllib.request

# Official raw mirrors of the CSIC 2010 HTTP Dataset
DATASET_FILES = {
    "normalTrafficTraining.txt": "https://raw.githubusercontent.com/leandrosilva/csic-2010/master/normalTrafficTraining.txt",
    "anomalousTrafficTest.txt": "https://raw.githubusercontent.com/leandrosilva/csic-2010/master/anomalousTrafficTest.txt"
}


def download_csic_benchmark():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    raw_dir = os.path.join(current_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    print("=" * 65)
    print(" STAGE 1: INGESTING CSIC 2010 HTTP BENCHMARK DATASET")
    print("=" * 65)

    for filename, url in DATASET_FILES.items():
        destination = os.path.join(raw_dir, filename)
        if os.path.exists(destination):
            print(f"[i] File already exists: {filename} ({os.path.getsize(destination)} bytes)")
            continue

        print(f"[*] Downloading {filename} from official repository...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as response, open(destination, "wb") as out:
                out.write(response.read())
            print(f"[+] Successfully saved {filename} ({os.path.getsize(destination)} bytes)")
        except Exception as e:
            print(f"[!] Error downloading {filename}: {e}")

    print("\n[+] Stage 1 Complete: Raw benchmark files ready in dataset/raw/\n")


if __name__ == "__main__":
    download_csic_benchmark()