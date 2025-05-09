import re
import requests
import tldextract
from urllib.parse import urlparse

import pyfiglet
i=pyfiglet.figlet_format("Check-the-Link")
print(i)

# Heuristic-based URL analyzer
def is_suspicious(url):
    suspicious_signals = 0

    # Check for IP address in URL
    if re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}', url):
        print("⚠️  Uses IP address instead of domain.")
        suspicious_signals += 1

    # Check for long URL
    if len(url) > 75:
        print("⚠️  URL is unusually long.")
        suspicious_signals += 1

    # Check for too many hyphens
    if url.count('-') > 4:
        print("⚠️  URL contains too many hyphens.")
        suspicious_signals += 1

    # Check for known phishing patterns
    phishing_keywords = ['login', 'secure', 'account', 'update', 'free', 'banking', 'ebayisapi']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        print("⚠️  URL contains phishing-related keywords.")
        suspicious_signals += 1

    # Check for multiple subdomains
    ext = tldextract.extract(url)
    if len(ext.subdomain.split('.')) > 2:
        print("⚠️  Too many subdomains in URL.")
        suspicious_signals += 1

    return suspicious_signals >= 2


# Optional: VirusTotal API checker
def check_with_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key
    }

    # Encode URL to base64 (without padding)
    url_id = requests.utils.quote(url)
    response = requests.post(vt_url, headers=headers, data={"url": url})
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        analysis_url = f"{vt_url}/{analysis_id}"
        report = requests.get(analysis_url, headers=headers).json()
        stats = report['data']['attributes']['last_analysis_stats']
        print("\n🔍 VirusTotal Scan Results:")
        print(f"  Harmless: {stats['harmless']}")
        print(f"  Malicious: {stats['malicious']}")
        print(f"  Suspicious: {stats['suspicious']}")
        return stats['malicious'] > 0 or stats['suspicious'] > 0
    else:
        print("❌ VirusTotal request failed.")
        return False

import base64
import json

def check_with_virustotal(url, api_key):
    headers = {
        "x-apikey": api_key
    }

    # Step 1: Encode the URL in base64 (URL-safe, no padding)
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Step 2: GET request to VirusTotal URL analysis
    vt_analysis_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    response = requests.get(vt_analysis_url, headers=headers)

    if response.status_code == 200:
        report = response.json()

        # Safety check: ensure 'data' and 'attributes' exist
        try:
            stats = report['data']['attributes']['last_analysis_stats']
            print("\n🔍 VirusTotal Scan Results:")
            print(f"  Harmless: {stats['harmless']}")
            print(f"  Malicious: {stats['malicious']}")
            print(f"  Suspicious: {stats['suspicious']}")
            return stats['malicious'] > 0 or stats['suspicious'] > 0
        except KeyError:
            print("⚠️  VirusTotal returned an unexpected response structure.")
            print(json.dumps(report, indent=2))  # Debugging aid
            return False
    else:
        print(f"❌ Failed to fetch report from VirusTotal (HTTP {response.status_code})")
        try:
            print(response.json())  # Detailed error message
        except:
            pass
        return False

# Main program
def main():
    url = input("Enter URL to check: ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print("\n🔎 Running heuristic analysis...")
    if is_suspicious(url):
        print("\n⚠️  Heuristic check suggests the URL may be malicious.")
    else:
        print("\n✅ Heuristic check suggests the URL appears safe.")

    use_vt = input("\nDo you want to check with VirusTotal? (y/n): ").lower()
    if use_vt == 'y':
        api_key = input("Enter your VirusTotal API key: ").strip()
        if check_with_virustotal(url, api_key):
            print("⚠️  VirusTotal analysis suggests this URL is malicious!")
        else:
            print("✅ VirusTotal analysis suggests the URL is safe.")

if __name__ == "__main__":
    main()
