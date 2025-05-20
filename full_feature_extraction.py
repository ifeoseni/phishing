import os
import socket
import ssl
import datetime
import pandas as pd
import requests
import whois
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm

INPUT_CSV = "remove_duplicate_from_combined_dataset.csv"
OUTPUT_CSV = "extracted_features.csv"

# === Utility Functions ===

def has_dns_record(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return 1
    except Exception:
        return 0

def get_whois_data(domain):
    try:
        return whois.whois(domain)
    except Exception:
        return {}

def get_ssl_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

def get_html_content(url):
    try:
        response = requests.get(url, timeout=10)
        return response.text
    except Exception:
        return ""

def extract_html_features(html):
    soup = BeautifulSoup(html, "html.parser")
    return {
        "num_links": len(soup.find_all("a")),
        "num_forms": len(soup.find_all("form")),
        "num_scripts": len(soup.find_all("script")),
        "num_iframes": len(soup.find_all("iframe")),
    }

# === Core Feature Extraction ===

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # fallback for URLs like "example.com/path"

    features = {
        "url": url,
        "has_dns_record": has_dns_record(domain),
        "domain_length": len(domain),
        "url_length": len(url),
    }

    # WHOIS features
    whois_data = get_whois_data(domain)
    creation_date = whois_data.get("creation_date")
    expiration_date = whois_data.get("expiration_date")

    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    features["domain_creation_date"] = creation_date
    features["domain_expiration_date"] = expiration_date
    features["domain_age_days"] = (
        (datetime.datetime.now() - creation_date).days if creation_date else None
    )

    # SSL certificate
    ssl_cert = get_ssl_certificate_info(domain)
    features["has_ssl"] = 1 if ssl_cert else 0
    if ssl_cert:
        features["ssl_issuer"] = ssl_cert.get("issuer", [("", "")])[0][0]
        not_after = ssl_cert.get("notAfter")
        if not_after:
            try:
                expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                features["ssl_expiry_days"] = (expiry_date - datetime.datetime.now()).days
            except ValueError:
                features["ssl_expiry_days"] = None
        else:
            features["ssl_expiry_days"] = None
    else:
        features["ssl_issuer"] = None
        features["ssl_expiry_days"] = None

    # HTML features
    html = get_html_content(url)
    html_features = extract_html_features(html)
    features.update(html_features)

    return features

# === Main Processing ===

def main():
    if not os.path.exists(INPUT_CSV):
        print(f"Input file '{INPUT_CSV}' not found.")
        return

    df = pd.read_csv(INPUT_CSV)
    urls = df['url'].dropna().unique()

    print(f"Extracting features from {len(urls)} URLs...\n")

    results = []
    for url in tqdm(urls):
        try:
            features = extract_features(url)
            results.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")

    result_df = pd.DataFrame(results)
    result_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nFeature extraction completed. Results saved to '{OUTPUT_CSV}'.")

if __name__ == "__main__":
    main()
