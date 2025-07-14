import requests
import validators
import tldextract
from urllib.parse import urlparse


def is_ip_address(domain):
    return all(part.isdigit() for part in domain.split('.'))
def detect_phishing_patterns(url):
    suspicious_keywords = ['login', 'secure', 'update', 'verify', 'account', 'webscr']
    domain = urlparse(url).netloc
    flags = []
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            flags.append(f"Suspicious keyword found: '{keyword}'")

    if is_ip_address(domain):
        flags.append("Uses IP address instead of domain")
    if '-' in domain:
        flags.append("Hyphenated domain (possible typosquatting)")

    return flags
def check_whois(domain):
    api_key = 'YOUR_API_NINJAS_KEY'  # Replace with your actual API key
    try:
        response = requests.get(
            f'https://api.api-ninjas.com/v1/whois?domain={domain}',
            headers={'X-Api-Key': api_key}
        )
        if response.status_code == 200:
            data = response.json()
            return f"Registered: {data.get('created', 'N/A')} | Expires: {data.get('expires', 'N/A')}"
        else:
            return f"API WHOIS error: {response.status_code}"
    except Exception as e:
        return f"API WHOIS failed: {str(e)}"
def scan_url(url):
    print(f"\n🔍 Scanning URL: {url}")

    if not validators.url(url):
        print("❌ Invalid URL format.")
        return

    domain = tldextract.extract(url).registered_domain
    flags = detect_phishing_patterns(url)
    whois_result = check_whois(domain)
    print(f"📁 Domain: {domain}")
    print(f"🌐 WHOIS: {whois_result}")

    if flags:
        print("⚠️ Suspicious Indicators:")
        for f in flags:
            print(" -", f)
    else:
        print("✅ No phishing patterns detected.")
if __name__ == "__main__":
    url_input = input("Enter a URL to scan: ")
    scan_url(ur_input)