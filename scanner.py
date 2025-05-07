#!/usr/bin/env python3

import requests
import re
import json
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""{Fore.GREEN}
  ____                  ____                                     
 / ___|  ___  ___ _ __ / ___|  ___  ___ _   _ _ __ ___  ___ _ __ 
 \___ \ / _ \/ _ \ '__| |  _  / _ \/ __| | | | '__/ __|/ _ \ '__|
  ___) |  __/  __/ |  | |_| | (_) \__ \ |_| | |  \__ \  __/ |   
 |____/ \___|\___|_|   \____|\___/|___/\__,_|_|  |___/\___|_|    

            {Fore.CYAN}Secu v1.0 - Website Secret Key Scanner
            {Style.RESET_ALL}"""

def load_patterns():
    return {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Stripe API Key": r'sk_live_[0-9a-zA-Z]{24}',
        "Generic Secret": r'(?i)(?:secret|password|token|key)[\s]*[:=][\s]*[\\"\']?([A-Za-z0-9_\-]{10,})[\\"\']?'
    }

def fetch_content(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch {url}: {e}")
        return None

def scan_url(url, patterns):
    content = fetch_content(url)
    if not content:
        return []
    
    findings = []
    for key_type, pattern in patterns.items():
        print(Fore.BLUE + f"[*] Scanning for {key_type}...")
        matches = re.findall(pattern, content)
        if matches:
            print(Fore.YELLOW + f"[!] Found {len(matches)} {key_type}(s)")
            findings.append({
                "type": key_type,
                "url": url,
                "keys": list(set(matches))
            })
        else:
            print(Fore.GREEN + f"[✓] No {key_type} found.")
    return findings

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="SecuScanner: Scan URLs for sensitive data")
    parser.add_argument("--url", "-u", help="Target URL to scan")
    parser.add_argument("--list", "-l", help="Path to file containing list of URLs")
    parser.add_argument("--json", "-j", action="store_true", help="Output result in JSON format")
    parser.add_argument("--output", "-o", help="Save result to file")
    args = parser.parse_args()

    if not args.url and not args.list:
        print(Fore.RED + "[ERROR] Please provide --url or --list")
        return

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[ERROR] Cannot read file: {e}")
            return

    all_results = []
    for target in targets:
        print(Fore.MAGENTA + f"\n[+] Scanning: {target}")
        patterns = load_patterns()
        results = scan_url(target, patterns)
        all_results.extend(results)

    if args.json:
        output = json.dumps(all_results, indent=4)
    else:
        output = "\n".join([f"{f['type']} found at {f['url']}: {', '.join(f['keys'])}" for f in all_results]) or "No sensitive data found."

    print("\n" + output)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
            print(Fore.CYAN + f"[+] Results saved to {args.output}")

    print(Fore.GREEN + "\n[✓] Scan completed.")

if __name__ == "__main__":
    main()
