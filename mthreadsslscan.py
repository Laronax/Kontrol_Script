import argparse
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

def run_sslscan(target, output_dir):
    sanitized_name = target.replace(":", "_").replace("/", "_")
    output_file = os.path.join(output_dir, f"{sanitized_name}.txt")
    try:
        with open(output_file, "w") as out:
            subprocess.run(["sslscan", target], stdout=out, stderr=subprocess.DEVNULL)
        print(f"[+] Tarama bitti: {target}")
    except Exception as e:
        print(f"[-] Hata {target}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Multithread Script")
    parser.add_argument("--input_file", help="Dosya Adi (Host:port formati ile)")
    parser.add_argument("--output_dir", help="Output dizini")
    parser.add_argument("--threads", type=int, default=10, help="Thread sayisi")

    args = parser.parse_args()

    # Create output directory if not exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Read targets
    with open(args.input_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    # Start scanning with threads
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for target in targets:
            executor.submit(run_sslscan, target, args.output_dir)

if __name__ == "__main__":
    main()
