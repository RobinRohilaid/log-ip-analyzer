import argparse
import re
import json
import requests
import ipaddress
from collections import Counter
import sys

def parse_arguments():
    """
    Sets up and parses command-line arguments (CLI).
    """
    parser = argparse.ArgumentParser(description="Log analysis script for checking IP addresses.")
    parser.add_argument("file_path", help="Path to the log file on the disk")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for filtering recurring IPs")
    parser.add_argument("--dry-run", action="store_true", help="Runs the script in test mode (no API requests)")
    return parser.parse_args()

def find_ip_addresses(file_path):
    """
    Reads the log file, finds all IP addresses using Regex, and validates them.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Regex pattern to find potential IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            raw_ips = re.findall(ip_pattern, content)
            
            # Validate IPs using Python's built-in ipaddress module
            valid_ips = []
            for ip in raw_ips:
                try:
                    ipaddress.ip_address(ip) # Throws ValueError if IP is invalid (e.g. 134.555.555.555)
                    valid_ips.append(ip)
                except ValueError:
                    pass
            return valid_ips
            
    except FileNotFoundError:
        print(f"ERROR: File '{file_path}' not found!")
        sys.exit(1)

def main():
    args = parse_arguments()
    print(f"Analyzing file: {args.file_path} (Threshold: {args.threshold})")
    
    all_ips = find_ip_addresses(args.file_path)
    if not all_ips:
        print("No valid IP addresses found in the log file.")
        return

    ip_counter = Counter(all_ips)
    suspicious_ips = {ip: count for ip, count in ip_counter.items() if count >= args.threshold}
    
    # Feature: If threshold is too high, show the most common IP
    if not suspicious_ips:
        max_ip = ip_counter.most_common(1)[0]
        print(f"No IPs met the threshold of {args.threshold}.")
        print(f"Highest occurrence found: {max_ip[0]} ({max_ip[1]} times). Try lowering the threshold.")
        return
    
    print(f"Found {len(suspicious_ips)} suspicious IP addresses (occurring >= {args.threshold} times).")
    report_data = []

    for ip, count in suspicious_ips.items():
        if args.dry_run:
            print(f"[DRY-RUN] IP: {ip} | Occurrences: {count}")
            report_data.append({"ip": ip, "count": count, "country": "DRY-RUN (API skipped)"})
        else:
            # NOTE: ip-api.com free tier only supports HTTP. HTTPS will return an error/403.
            url = f"http://ip-api.com/json/{ip}"
            try:
                response = requests.get(url, timeout=5)
                response.raise_for_status() 
                
                data = response.json()
                country = data.get('country', 'Unknown')
                
                print(f"IP: {ip} | Occurrences: {count} | Country: {country}")
                report_data.append({"ip": ip, "count": count, "country": country})
                
            except requests.exceptions.RequestException as e:
                print(f"Error querying IP {ip}: {e}")
                report_data.append({"ip": ip, "count": count, "country": "API ERROR"})

    if not args.dry_run and report_data:
        with open("threat_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print("\nReport successfully saved to: threat_report.json")

if __name__ == "__main__":
    main()