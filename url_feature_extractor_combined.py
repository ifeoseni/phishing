# url_feature_extractor_combined.py
import re
import pandas as pd
import requests
import tldextract
import math
import argparse
import os
import urllib3
from urllib.parse import urlparse, parse_qs
from collections import Counter
import time

# Disable warnings for insecure requests (e.g., self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
SUSPICIOUS_TLDS = {
    "xyz", "club", "top", "info", "tk", "ru", "biz", "ws", "name", "online", "site",
    "pw", "link", "click", "support", "account", "service", "security", "update",
    "network", "loan", "work", "review", "vip", "live", "stream", "download", "win"
}

SUSPICIOUS_KEYWORDS = {
    "login", "secure", "account", "update", "verify", "signin", "banking", "confirm",
    "password", "credential", "support", "service", "recover", "admin", "cmd", "webscr",
    "paypal", "ebay", "apple", "microsoft", "google", "amazon", "wellsfargo", "chase",
    "bankofamerica", "irs", "official", "billing", "authentication", "session", "alert"
}

SHORTENING_SERVICES = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "j.mp", "youtu.be", "rebrand.ly", "tiny.cc", "lc.chat", "rb.gy"
}

# Common brand names (lowercase, partial matches allowed)
# This list should be expanded significantly for real-world use
COMMON_BRANDS = {
    "google", "facebook", "youtube", "amazon", "wikipedia", "twitter", "instagram",
    "linkedin", "microsoft", "apple", "paypal", "netflix", "ebay", "reddit", "bing",
    "wordpress", "adobe", "whatsapp", "tiktok", "snapchat", "pinterest", "chase",
    "bankofamerica", "wellsfargo", "citibank", "usbank", "hsbc", "barclays", "fedex",
    "ups", "dhl", "irs", "gov", "cloudflare", "godaddy", "verisign"
}

SENSITIVE_FILE_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "scr", "js", "vbs", "ps1", "sh", "jar", "msi", "dmg"
}

# --- Helper Functions ---

def ensure_scheme(url):
    """Adds http scheme if missing."""
    if not re.match(r"^[a-zA-Z]+://", url):
        # Check if it looks like a path or just a domain
        if "/" in url or "." not in url:
             # Cannot reliably determine scheme for path-like strings without domain
             return url # Return as is, parsing will likely fail gracefully
        return "http://" + url
    return url

def calculate_entropy(text):
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def get_word_stats(text):
    """Calculates statistics on words in a string (split by non-alphanumeric)."""
    words = re.split(r"[^a-zA-Z0-9]+", text)
    words = [word for word in words if word] # Remove empty strings
    if not words:
        return {"num_words": 0, "avg_word_length": 0, "max_word_length": 0, "min_word_length": 0}
    word_lengths = [len(word) for word in words]
    return {
        "num_words": len(words),
        "avg_word_length": sum(word_lengths) / len(words),
        "max_word_length": max(word_lengths),
        "min_word_length": min(word_lengths)
    }

def check_http_status(url):
    """Checks the HTTP status and activity of a URL.

    Returns:
        Tuple of (http_status, is_active)
        http_status: Final HTTP status code (0 if no response/error, -1 for timeout, -2 for connection error, -3 for redirects).
        is_active: 1 if the server responded (any status code), 0 otherwise.
    """
    url_with_scheme = ensure_scheme(url)
    http_status = 0
    is_active = 0

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(
            url_with_scheme,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=False
        )
        http_status = response.status_code
        is_active = 1

    except requests.exceptions.Timeout:
        print(f"Timeout error for {url}")
        http_status = -1
        is_active = 0
    except requests.exceptions.ConnectionError:
        print(f"Connection error for {url}")
        http_status = -2
        is_active = 0
    except requests.exceptions.TooManyRedirects:
        print(f"Too many redirects for {url}")
        http_status = -3
        is_active = 1 # It was active initially
    except requests.exceptions.RequestException as e:
        print(f"Request exception for {url}: {e}")
        http_status = 0
        is_active = 0
    except Exception as e:
        print(f"Unexpected error during HTTP check for {url}: {e}")
        http_status = 0
        is_active = 0

    return http_status, is_active

# --- Main Feature Extraction Function ---

def extract_features(url):
    """Extracts combined lexical and basic HTTP features from a given URL."""
    features = {}
    original_url = url
    url_for_parsing = ensure_scheme(url)

    # Initialize HTTP features
    features["http_status"] = 0
    features["is_active"] = 0

    try:
        # --- Basic URL Parsing ---
        parsed_url = urlparse(url_for_parsing)
        scheme = parsed_url.scheme
        hostname = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        fragment = parsed_url.fragment

        # Handle potential port in hostname
        hostname_no_port = hostname
        port = None
        if ":" in hostname:
            parts = hostname.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                hostname_no_port = parts[0]
                port = int(parts[1])
                features["has_port"] = 1
                features["is_standard_port"] = 1 if (scheme == "http" and port == 80) or \
                                                    (scheme == "https" and port == 443) else 0
            else:
                 # Invalid port format, treat as part of hostname for analysis
                 features["has_port"] = 0
                 features["is_standard_port"] = 0
        else:
            features["has_port"] = 0
            features["is_standard_port"] = 0

        # --- TLDExtract ---
        try:
            ext = tldextract.extract(hostname_no_port)
            domain = ext.registered_domain if ext.registered_domain else hostname_no_port
            subdomain = ext.subdomain
            tld = ext.suffix
        except Exception as e:
            print(f"TLDExtract error for {hostname_no_port}: {e}")
            # Fallback if tldextract fails
            parts = hostname_no_port.split(".")
            if len(parts) > 1:
                tld = parts[-1]
                domain = parts[-2] + "." + tld
                subdomain = ".".join(parts[:-2])
            else:
                domain = hostname_no_port
                subdomain = ""
                tld = ""

        # --- Length Features ---
        features["url_length"] = len(original_url)
        features["hostname_length"] = len(hostname_no_port)
        features["path_length"] = len(path)
        features["query_length"] = len(query)
        features["fragment_length"] = len(fragment)
        features["tld_length"] = len(tld)
        features["domain_length"] = len(domain)
        features["subdomain_length"] = len(subdomain)

        # --- Count Features (URL Structure) ---
        path_segments = [seg for seg in path.split("/") if seg]
        features["num_path_segments"] = len(path_segments)
        features["directory_depth"] = path.count("/") -1 if path.endswith("/") else path.count("/")
        try:
            query_params = parse_qs(query)
            features["num_query_params"] = len(query_params)
            features["avg_param_name_length"] = sum(len(k) for k in query_params.keys()) / len(query_params) if query_params else 0
            features["avg_param_value_length"] = sum(len(v[0]) for v in query_params.values() if v) / len(query_params) if query_params else 0
        except ValueError:
            features["num_query_params"] = query.count("&") + 1 if query else 0
            features["avg_param_name_length"] = 0
            features["avg_param_value_length"] = 0

        subdomain_parts = [part for part in subdomain.split(".") if part]
        features["num_subdomains"] = len(subdomain_parts)
        # Refined has_subdomain: 1 if subdomains exist AND are not just 'www'
        features["has_meaningful_subdomain"] = 1 if features["num_subdomains"] > 0 and not (features["num_subdomains"] == 1 and subdomain_parts[0] == "www") else 0
        features["has_www"] = 1 if "www" in subdomain_parts else 0

        # --- Boolean/Categorical Features ---
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        features["is_ip_address"] = 1 if re.match(ip_pattern, hostname_no_port) else 0
        features["uses_https"] = 1 if scheme == "https" else 0
        features["is_punycode"] = 1 if hostname_no_port.startswith("xn--") or ".xn--" in hostname_no_port else 0

        # --- Character Count Features (Whole URL) ---
        features["num_dots"] = original_url.count(".")
        features["num_hyphens"] = original_url.count("-")
        features["num_underscores"] = original_url.count("_")
        features["num_equals"] = original_url.count("=")
        features["num_ampersands"] = original_url.count("&")
        features["num_slashes"] = original_url.count("/")
        features["num_question_marks"] = original_url.count("?")
        features["num_percent"] = original_url.count("%") # URL encoding
        features["num_plus"] = original_url.count("+")
        features["num_at"] = original_url.count("@") # Often suspicious
        features["num_tilde"] = original_url.count("~")
        features["num_commas"] = original_url.count(",")
        features["num_semicolons"] = original_url.count(";")
        features["num_dollar"] = original_url.count("$")
        features["num_spaces"] = original_url.count(" ")
        features["num_hash"] = original_url.count("#")
        sensitive_chars = ";()<>`\"\\'" # Added more
        features["num_sensitive_chars"] = sum(original_url.count(char) for char in sensitive_chars)

        # --- Character Count Features (Specific Parts) ---
        features["num_dots_hostname"] = hostname_no_port.count(".")
        features["num_hyphens_hostname"] = hostname_no_port.count("-")
        features["num_underscores_hostname"] = hostname_no_port.count("_")
        features["num_dots_path"] = path.count(".")
        features["num_hyphens_path"] = path.count("-")
        features["num_underscores_path"] = path.count("_")
        features["num_slashes_path"] = path.count("/")
        features["num_equals_query"] = query.count("=")
        features["num_ampersands_query"] = query.count("&")

        # --- Character Type Features (Whole URL) ---
        digits = sum(c.isdigit() for c in original_url)
        letters = sum(c.isalpha() for c in original_url)
        uppercase = sum(c.isupper() for c in original_url)
        lowercase = sum(c.islower() for c in original_url)
        special_chars = len(original_url) - digits - letters
        features["num_digits"] = digits
        features["num_letters"] = letters
        features["num_uppercase"] = uppercase
        features["num_lowercase"] = lowercase
        features["digit_ratio_url"] = digits / features["url_length"] if features["url_length"] > 0 else 0
        features["letter_ratio_url"] = letters / features["url_length"] if features["url_length"] > 0 else 0
        features["special_char_ratio_url"] = special_chars / features["url_length"] if features["url_length"] > 0 else 0
        features["uppercase_ratio_url"] = uppercase / features["url_length"] if features["url_length"] > 0 else 0

        # --- Character Type Features (Specific Parts) ---
        digits_hostname = sum(c.isdigit() for c in hostname_no_port)
        letters_hostname = sum(c.isalpha() for c in hostname_no_port)
        features["num_digits_hostname"] = digits_hostname
        features["digit_ratio_hostname"] = digits_hostname / features["hostname_length"] if features["hostname_length"] > 0 else 0
        features["has_hex_in_hostname"] = 1 if re.search(r"[0-9a-fA-F]{4,}", hostname_no_port) else 0

        digits_path = sum(c.isdigit() for c in path)
        letters_path = sum(c.isalpha() for c in path)
        features["num_digits_path"] = digits_path
        features["digit_ratio_path"] = digits_path / features["path_length"] if features["path_length"] > 0 else 0
        features["has_hex_in_path"] = 1 if re.search(r"[0-9a-fA-F]{4,}", path) else 0

        # --- Path/File Features ---
        filename = ""
        file_ext = ""
        if path_segments:
            filename = path_segments[-1]
            features["filename_length"] = len(filename)
            if "." in filename:
                parts = filename.split(".")
                if len(parts) > 1 and parts[-1]: # Ensure extension exists
                    file_ext = parts[-1].lower()
                    features["has_file_extension"] = 1
                    features["file_extension_length"] = len(file_ext)
                    features["has_sensitive_extension"] = 1 if file_ext in SENSITIVE_FILE_EXTENSIONS else 0
                else:
                    features["has_file_extension"] = 0
                    features["file_extension_length"] = 0
                    features["has_sensitive_extension"] = 0
            else:
                features["has_file_extension"] = 0
                features["file_extension_length"] = 0
                features["has_sensitive_extension"] = 0
            features["avg_dir_length"] = sum(len(seg) for seg in path_segments[:-1]) / (len(path_segments) - 1) if len(path_segments) > 1 else 0
        else:
            features["filename_length"] = 0
            features["has_file_extension"] = 0
            features["file_extension_length"] = 0
            features["has_sensitive_extension"] = 0
            features["avg_dir_length"] = 0

        features["path_contains_dots"] = 1 if ".." in path_segments else 0 # Check for directory traversal attempts
        features["path_contains_tilde"] = 1 if "~" in path else 0
        features["path_ends_with_slash"] = 1 if path.endswith("/") and len(path) > 1 else 0

        # --- Entropy Features ---
        features["entropy_url"] = calculate_entropy(original_url)
        features["entropy_hostname"] = calculate_entropy(hostname_no_port)
        features["entropy_domain"] = calculate_entropy(domain)
        features["entropy_subdomain"] = calculate_entropy(subdomain)
        features["entropy_path"] = calculate_entropy(path)
        features["entropy_query"] = calculate_entropy(query)
        features["entropy_filename"] = calculate_entropy(filename)
        features["entropy_extension"] = calculate_entropy(file_ext)

        # --- Word Statistics Features ---
        hostname_words_stats = get_word_stats(hostname_no_port)
        features["hostname_num_words"] = hostname_words_stats["num_words"]
        features["hostname_avg_word_length"] = hostname_words_stats["avg_word_length"]
        features["hostname_max_word_length"] = hostname_words_stats["max_word_length"]

        path_words_stats = get_word_stats(path)
        features["path_num_words"] = path_words_stats["num_words"]
        features["path_avg_word_length"] = path_words_stats["avg_word_length"]
        features["path_max_word_length"] = path_words_stats["max_word_length"]

        query_words_stats = get_word_stats(query)
        features["query_num_words"] = query_words_stats["num_words"]
        features["query_avg_word_length"] = query_words_stats["avg_word_length"]
        features["query_max_word_length"] = query_words_stats["max_word_length"]

        # --- Suspicious Elements ---
        features["has_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

        # Check keywords in hostname, path, query, fragment
        url_text_parts = f"{hostname_no_port} {path} {query} {fragment}".lower()
        found_keywords = {kw for kw in SUSPICIOUS_KEYWORDS if kw in url_text_parts}
        features["has_suspicious_keywords"] = 1 if found_keywords else 0
        features["num_suspicious_keywords"] = len(found_keywords)

        # Check for brand names in hostname (subdomain or domain)
        hostname_lower = hostname_no_port.lower()
        found_brands = {brand for brand in COMMON_BRANDS if brand in hostname_lower}
        features["contains_brand_name"] = 1 if found_brands else 0
        # More specific: check if brand is in subdomain but not domain (potential phishing)
        subdomain_lower = subdomain.lower()
        domain_lower = domain.lower()
        features["brand_in_subdomain_only"] = 0
        if found_brands:
             for brand in found_brands:
                 if brand in subdomain_lower and brand not in domain_lower:
                     features["brand_in_subdomain_only"] = 1
                     break
        # Check if domain itself is a suspicious keyword
        domain_base = domain.split('.')[0] # e.g., 'paypal' from 'paypal.com'
        features["domain_is_suspicious_keyword"] = 1 if domain_base in SUSPICIOUS_KEYWORDS else 0


        features["uses_shortening_service"] = 1 if domain in SHORTENING_SERVICES else 0
        features["path_contains_ip"] = 1 if re.search(ip_pattern, path) else 0
        features["query_contains_url"] = 1 if re.search(r"https?%3A%2F%2F|https?://", query, re.IGNORECASE) else 0

        # --- HTTP Check ---
        # Perform this last as it requires network access
        http_status, is_active = check_http_status(original_url)
        features["http_status"] = http_status
        features["is_active"] = is_active

        # Ensure all features are numeric
        for key, value in features.items():
            if not isinstance(value, (int, float)):
                features[key] = 0 # Default non-numeric to 0

    except Exception as e:
        print(f"Error processing URL ", original_url, f": {e}")
        # Define all expected feature keys for consistent error output
        feature_keys = [
            "url_length", "hostname_length", "path_length", "query_length", "fragment_length",
            "tld_length", "domain_length", "subdomain_length", "num_path_segments", "directory_depth",
            "num_query_params", "avg_param_name_length", "avg_param_value_length", "num_subdomains",
            "has_meaningful_subdomain", "has_www", "is_ip_address", "has_port", "is_standard_port",
            "uses_https", "is_punycode", "num_dots", "num_hyphens", "num_underscores", "num_equals",
            "num_ampersands", "num_slashes", "num_question_marks", "num_percent", "num_plus",
            "num_at", "num_tilde", "num_commas", "num_semicolons", "num_dollar", "num_spaces",
            "num_hash", "num_sensitive_chars", "num_dots_hostname", "num_hyphens_hostname",
            "num_underscores_hostname", "num_dots_path", "num_hyphens_path", "num_underscores_path",
            "num_slashes_path", "num_equals_query", "num_ampersands_query", "num_digits", "num_letters",
            "num_uppercase", "num_lowercase", "digit_ratio_url", "letter_ratio_url",
            "special_char_ratio_url", "uppercase_ratio_url", "num_digits_hostname",
            "digit_ratio_hostname", "has_hex_in_hostname", "num_digits_path", "digit_ratio_path",
            "has_hex_in_path", "filename_length", "has_file_extension", "file_extension_length",
            "has_sensitive_extension", "avg_dir_length", "path_contains_dots", "path_contains_tilde",
            "path_ends_with_slash", "entropy_url", "entropy_hostname", "entropy_domain",
            "entropy_subdomain", "entropy_path", "entropy_query", "entropy_filename", "entropy_extension",
            "hostname_num_words", "hostname_avg_word_length", "hostname_max_word_length",
            "path_num_words", "path_avg_word_length", "path_max_word_length", "query_num_words",
            "query_avg_word_length", "query_max_word_length", "has_suspicious_tld",
            "has_suspicious_keywords", "num_suspicious_keywords", "contains_brand_name",
            "brand_in_subdomain_only", "domain_is_suspicious_keyword", "uses_shortening_service",
            "path_contains_ip", "query_contains_url", "http_status", "is_active"
        ]
        features = {key: 0 for key in feature_keys} # Default all to 0 on error
        features["error"] = 1 # Add error flag

    # Add URL and error flag (0 if successful)
    features["url"] = original_url
    if "error" not in features:
        features["error"] = 0

    # Reorder columns for clarity
    ordered_keys = ["url", "error", "http_status", "is_active"] + sorted([k for k in features if k not in ["url", "error", "http_status", "is_active"]])
    ordered_features = {k: features.get(k, 0) for k in ordered_keys} # Use get with default 0

    return ordered_features

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Extract combined lexical and HTTP features from URLs.")
    parser.add_argument("input", help="Input file containing URLs (one per line) or a single URL string.")
    parser.add_argument("-o", "--output", default="combined_features.csv", help="Output CSV file name.")
    args = parser.parse_args()

    urls = []
    if os.path.isfile(args.input):
        try:
            with open(args.input, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading input file {args.input}: {e}")
            return
    else:
        urls = [args.input]

    if not urls:
        print("No valid URLs found in input.")
        return

    all_features = []
    total_urls = len(urls)
    print(f"Processing {total_urls} URL(s)...")
    start_time = time.time()

    for i, url in enumerate(urls):
        print(f"Processing URL {i+1}/{total_urls}: {url}")
        features = extract_features(url)
        all_features.append(features)
        # Optional: Add a small delay to avoid overwhelming servers
        # time.sleep(0.1)

    end_time = time.time()
    print(f"\nFinished processing in {end_time - start_time:.2f} seconds.")

    if not all_features:
        print("No features extracted.")
        return

    try:
        df = pd.DataFrame(all_features)
        # Ensure consistent column order based on the first successful extraction
        first_valid_features = next((f for f in all_features if not f.get("error", 1)), None)
        if first_valid_features:
            ordered_columns = list(first_valid_features.keys())
            existing_columns = [col for col in ordered_columns if col in df.columns]
            df = df[existing_columns]
        else:
            print("Warning: All URLs failed processing. Outputting error flags.")
            if "url" in df.columns and "error" in df.columns:
                 df = df[["url", "error"]]

        df.to_csv(args.output, index=False)
        print(f"Features extracted and saved to {args.output}")
        feature_count = len(df.columns) - sum(1 for col in ["url", "error"] if col in df.columns)
        print(f"Number of features extracted per URL: {feature_count}")

    except Exception as e:
        print(f"Error creating DataFrame or saving CSV: {e}")

if __name__ == "__main__":
    main()

