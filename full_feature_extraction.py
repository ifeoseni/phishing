import os
import re
import pandas as pd
import requests
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
import urllib3
import warnings
import time
from typing import Tuple, Optional, Dict, Any

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# List of suspicious TLDs
SUSPICIOUS_TLDS = ['xyz', 'club', 'top', 'info', 'tk', 'ru', 'biz', 'ws', 'name', 'online']

# Global set to track all encountered TLDs
ENCOUNTERED_TLDS = set()

def ensure_url_scheme(url: str) -> str:
    """Ensure URL has http:// or https:// scheme"""
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return f'http://{url}'
    return url

def normalize_domain(domain: str) -> str:
    """Normalize domain by removing protocol and path"""
    domain = re.sub(r'^https?://', '', domain, flags=re.IGNORECASE)
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    return domain.split('/')[0].strip()

def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain"""
    def get_domain(u):
        parsed = urlparse(ensure_url_scheme(u))
        domain = parsed.netloc.split(':')[0]  # Remove port
        return tldextract.extract(domain).registered_domain
    
    return get_domain(url1) == get_domain(url2)

def get_domain_age_and_expiry(domain: str) -> Tuple[Optional[int], Optional[int]]:
    """Get domain age in days and days until expiration"""
    try:
        domain = normalize_domain(domain)
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
            
        age_days = (datetime.now() - creation_date).days if creation_date else None
        expiry_days = (expiry_date - datetime.now()).days if expiry_date else None
        
        return age_days, expiry_days
    except Exception as e:
        print(f"WHOIS error for {domain}: {e}")
        return None, None

def check_http(url: str) -> Tuple[int, int, int, str, int]:
    """Check HTTP response with improved status code handling
    
    Returns:
        Tuple of:
        - http_status: The final HTTP status code
        - server_responded: 1 if server responded (any HTTP status), 0 if no response
        - has_redirect: 1 if redirected outside original domain
        - final_url: The final URL after redirects
        - is_active: 1 if URL exists (any response including 4xx/5xx), 0 if no response
    """
    final_url = url
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        url_with_scheme = ensure_url_scheme(url)
        
        # First make a HEAD request without following redirects
        try:
            no_redirect_response = requests.head(
                url_with_scheme,
                headers=headers,
                timeout=10,
                allow_redirects=False,
                verify=False
            )
            
            # Server responded (any HTTP status means the URL exists)
            server_responded = 1
            is_active = 1
            
            # Check for redirect headers
            if no_redirect_response.is_redirect and 'Location' in no_redirect_response.headers:
                location = no_redirect_response.headers['Location']
                if not is_same_domain(url, location):
                    return no_redirect_response.status_code, 1, 1, location, 1
        
        except requests.exceptions.SSLError:
            # If SSL error, try without verification
            no_redirect_response = requests.head(
                url_with_scheme,
                headers=headers,
                timeout=10,
                allow_redirects=False,
                verify=False
            )
            
            server_responded = 1
            is_active = 1
            
            if no_redirect_response.is_redirect and 'Location' in no_redirect_response.headers:
                location = no_redirect_response.headers['Location']
                if not is_same_domain(url, location):
                    return no_redirect_response.status_code, 1, 1, location, 1
        
        # Now make the full request following redirects
        response = requests.get(
            url_with_scheme,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=False
        )
        final_url = response.url
        server_responded = 1
        is_active = 1
        
        # Check if we were redirected outside original domain
        has_redirect = 0
        if len(response.history) > 0:
            for resp in response.history:
                if resp.is_redirect and 'Location' in resp.headers:
                    if not is_same_domain(url, resp.headers['Location']):
                        has_redirect = 1
                        break
        
        return response.status_code, server_responded, has_redirect, final_url, is_active
        
    except Exception as e:
        print(f"HTTP check error for {url}: {e}")
        if isinstance(e, (requests.exceptions.ConnectionError, 
                         requests.exceptions.Timeout,
                         requests.exceptions.TooManyRedirects)):
            # No server response or unreachable
            return 0, 0, 0, url, 0
        elif isinstance(e, requests.exceptions.RequestException):
            # Other request exceptions (treated as server responded)
            return 0, 1, 0, url, 1
        else:
            # Unknown error (treated as no response)
            return 0, 0, 0, url, 0

def check_ssl(url: str) -> Tuple[int, Optional[int]]:
    """Check SSL certificate for the original URL/domain only"""
    try:
        parsed = urlparse(ensure_url_scheme(url))
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expiry_days = (expire_date - datetime.now()).days
                    return 1, expiry_days
        return 0, None
    except Exception as e:
        print(f"SSL check error for {url}: {e}")
        return 0, None

def check_dns_records(domain: str) -> Dict[str, Any]:
    """Check various DNS records for a domain"""
    results = {
        'dns_a_presence': 0,
        'dns_a_count': 0,
        'dns_mx_presence': 0,
        'dns_mx_count': 0,
        'dns_txt_presence': 0,
        'dns_txt_count': 0,
        'dns_ns_presence': 0,
        'dns_ns_count': 0,
        'dns_spf_presence': 0,
        'dns_spf_count': 0,
        'dns_dkim_presence': 0,
        'dns_dkim_count': 0,
        'dns_dmarc_presence': 0,
        'dns_dmarc_count': 0,
        'dns_cname_presence': 0,
        'dns_cname_count': 0,
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]  # Use Google DNS
        domain = normalize_domain(domain)
        
        # A records
        try:
            a_records = resolver.resolve(domain, 'A')
            results.update({
                'dns_a_presence': 1,
                'dns_a_count': len(a_records)
            })
        except:
            pass
        
        # MX records
        try:
            mx_records = resolver.resolve(domain, 'MX')
            results.update({
                'dns_mx_presence': 1,
                'dns_mx_count': len(mx_records)
            })
        except:
            pass
        
        # TXT records
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            txt_count = len(txt_records)
            results.update({
                'dns_txt_presence': 1 if txt_count > 0 else 0,
                'dns_txt_count': txt_count
            })
            
            # Check for SPF, DKIM, DMARC in TXT records
            spf_count = 0
            dkim_count = 0
            dmarc_count = 0
            
            for record in txt_records:
                record_text = ' '.join([s.decode('utf-8') for s in record.strings])
                if 'v=spf1' in record_text.lower():
                    spf_count += 1
                if 'v=dkim1' in record_text.lower():
                    dkim_count += 1
                if 'v=dmarc1' in record_text.lower():
                    dmarc_count += 1
            
            results.update({
                'dns_spf_presence': 1 if spf_count > 0 else 0,
                'dns_spf_count': spf_count,
                'dns_dkim_presence': 1 if dkim_count > 0 else 0,
                'dns_dkim_count': dkim_count,
                'dns_dmarc_presence': 1 if dmarc_count > 0 else 0,
                'dns_dmarc_count': dmarc_count
            })
        except:
            pass
        
        # NS records
        try:
            ns_records = resolver.resolve(domain, 'NS')
            results.update({
                'dns_ns_presence': 1,
                'dns_ns_count': len(ns_records)
            })
        except:
            pass
        
        # CNAME records
        try:
            cname_records = resolver.resolve(domain, 'CNAME')
            results.update({
                'dns_cname_presence': 1,
                'dns_cname_count': len(cname_records)
            })
        except:
            pass
        
    except Exception as e:
        print(f"DNS check error for {domain}: {e}")
    
    return results

def check_html_features(url: str) -> Dict[str, Any]:
    """Extract HTML features using BeautifulSoup"""
    features = {
        'has_title': 0,
        'title_length': 0,
        'has_iframe': 0,
        'has_text_input': 0,
        'has_password_input': 0,
        'has_button': 0,
        'has_image': 0,
        'has_submit': 0,
        'has_link': 0,
        'has_error': 0,
        'num_links': 0,
        'num_images': 0,
        'num_scripts': 0,
        'num_iframes': 0,
        'has_javascript': 0,
        'has_favicon': 0,
        'num_a_tags': 0,
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(
            ensure_url_scheme(url),
            headers=headers,
            timeout=10,
            verify=False
        )
        
        # Check if response is HTML
        if 'text/html' not in response.headers.get('Content-Type', ''):
            return features
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Title tag
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            title_text = title_tag.string.strip()
            features.update({
                'has_title': 1,
                'title_length': len(title_text)
            })
        
        # Form elements
        features.update({
            'has_text_input': 1 if soup.find('input', {'type': 'text'}) else 0,
            'has_password_input': 1 if soup.find('input', {'type': 'password'}) else 0,
            'has_button': 1 if soup.find('button') else 0,
            'has_submit': 1 if soup.find('input', {'type': 'submit'}) else 0,
            'has_error': 1 if soup.find(string=re.compile(r'error|not found|404', re.I)) else 0
        })
        
        # Count elements first
        iframe_count = len(soup.find_all('iframe'))
        script_count = len(soup.find_all('script'))
        link_count = len(soup.find_all('a'))
        img_count = len(soup.find_all('img'))
        
        # Check for favicon
        favicon = soup.find('link', rel=re.compile('icon|shortcut icon', re.I))
        
        # Update features with counts and flags
        features.update({
            'num_links': link_count,
            'num_images': img_count,
            'num_scripts': script_count,
            'num_iframes': iframe_count,
            'has_iframe': 1 if iframe_count > 0 else 0,
            'has_image': 1 if img_count > 0 else 0,
            'has_link': 1 if link_count > 0 else 0,
            'has_javascript': 1 if script_count > 0 else 0,
            'has_favicon': 1 if favicon else 0,
            'num_a_tags': link_count  # Same as num_links
        })
        
    except Exception as e:
        print(f"HTML check error for {url}: {e}")
    
    return features

def count_url_special_chars(url: str) -> Dict[str, int]:
    """Count special characters in URL"""
    return {
        'num_at': url.count('@'),
        'has_at': 1 if '@' in url else 0,
        'num_tilde': url.count('~'),
        'has_tilde': 1 if '~' in url else 0,
        'num_underscore': url.count('_'),
        'has_underscore': 1 if '_' in url else 0,
        'num_percent': url.count('%'),
        'has_percent': 1 if '%' in url else 0,
        'num_hash': url.count('#'),
        'has_hash': 1 if '#' in url else 0,
        'num_dollar': url.count('$'),
        'has_dollar': 1 if '$' in url else 0,
        'num_colon': url.count(':'),
        'has_colon': 1 if ':' in url else 0,
    }

def count_url_chars(url: str) -> Dict[str, int]:
    """Count character types in URL"""
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    vowels = sum(1 for c in url.lower() if c in 'aeiou')
    consonants = letters - vowels
    
    return {
        'num_digits': digits,
        'has_digits': 1 if digits > 0 else 0,
        'num_letters': letters,
        'has_letters': 1 if letters > 0 else 0,
        'num_vowels': vowels,
        'num_consonants': consonants,
        'digit_ratio': digits / len(url) if url else 0,
    }

def extract_url_features(url: str) -> Optional[Dict[str, Any]]:
    try:
        # Keep original domain
        original_domain = normalize_domain(url)
        
        # Extract components for feature calculation
        parsed = urlparse(ensure_url_scheme(url))
        netloc = parsed.netloc.split(':')[0]  # Remove port if present
        extracted = tldextract.extract(netloc)
        
        # Get the TLD and update global set
        tld = extracted.suffix.lower()
        ENCOUNTERED_TLDS.add(tld)
        
        # Create one-hot encoded TLD features
        tld_features = {f'tld_{tld}': 0 for tld in ENCOUNTERED_TLDS}
        tld_features[f'tld_{tld}'] = 1
        
        # Fix subdomain extraction
        subdomain = extracted.subdomain
        subdomain_parts = subdomain.split('.') if subdomain else []
        
        # If the only subdomain is 'www', we consider it as no subdomain
        if len(subdomain_parts) == 1 and subdomain_parts[0].lower() == 'www':
            has_subdomain = 0
            subdomain_count = 0
            subdomain = None
        else:
            has_subdomain = 1 if subdomain else 0
            subdomain_count = len(subdomain_parts) if subdomain else 0
        
        # Calculate domain features
        features = {
            # 'url': original_domain,
            'domain_length': len(extracted.domain),
            # 'subdomain': subdomain,
            # 'subdomain_count': subdomain_count,
            'has_subdomain': has_subdomain,
            'has_www': 1 if 'www' in netloc.lower() else 0,
            # 'tld': tld,  # Maintain original tld column
            'is_ip': 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', extracted.domain) else 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_slash': url.count('/'),
            'num_question': url.count('?'),
            'num_equal': url.count('='),
            'num_ampersand': url.count('&'),
            'has_http': 1 if url.lower().startswith('http://') else 0,
            # 'has_http': 1 if url.lower().startswith('http://') else 0,
            'has_port': 1 if ':' in parsed.netloc else 0,
            'has_at': 1 if '@' in url else 0,
            'suspicious_tld': 1 if extracted.suffix in SUSPICIOUS_TLDS else 0,
            'has_login': 1 if re.search(r'login|signin|auth', url, re.I) else 0,
            'has_register': 1 if re.search(r'register|signup', url, re.I) else 0,
            # 'has_brand': 1 if re.search(r'paypal|ebay|amazon|bank|apple|microsoft', url, re.I) else 0,
            # 'has_hex': 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0,
            # 'punycode': 1 if 'xn--' in url else 0,
            'shortened': 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co', url, re.I) else 0,
            'full_url_length': len(url),
        }
        
        # Add the one-hot encoded TLD features
        features.update(tld_features)
        
        # Add special character counts
        features.update(count_url_special_chars(url))
        
        # Add character type counts
        features.update(count_url_chars(url))
        
        # Get domain age and expiry
        age_days, expiry_days = get_domain_age_and_expiry(url)
        features.update({
            'domain_age_days': age_days,
            'time_to_expiration': expiry_days
        })
        
        # HTTP features with improved response detection
        http_status, server_responded, has_redirect, final_url, is_active = check_http(url)
        features.update({
            'http_status': http_status,
            'server_responded': server_responded,
            'has_redirect': has_redirect,
            # 'final_url': final_url,
            # Add is_active last to ensure it appears as the final column
            'is_active': is_active
        })
        
        # SSL features for original domain (not final_url)
        has_ssl, ssl_expiry_days = check_ssl(url)
        features.update({
            'has_ssl': has_ssl,
            'ssl_expiry_days': ssl_expiry_days
        })
        
        # DNS features
        dns_features = check_dns_records(url)
        features.update(dns_features)
        
        # HTML features (only if server responded)
        if server_responded == 1:
            html_features = check_html_features(url if has_redirect == 0 else final_url)
            features.update(html_features)
        else:
            # Initialize all HTML features to 0
            html_features = {
                'has_title': 0,
                'title_length': 0,
                'has_iframe': 0,
                'has_text_input': 0,
                'has_password_input': 0,
                'has_button': 0,
                'has_image': 0,
                'has_submit': 0,
                'has_link': 0,
                'has_error': 0,
                'num_links': 0,
                'num_images': 0,
                'num_scripts': 0,
                'num_iframes': 0,
                'has_javascript': 0,
                'has_favicon': 0,
                'num_a_tags': 0,
            }
            features.update(html_features)
        
        return features
    except Exception as e:
        print(f"Error processing {url}: {e}")
        return None

def process_urls(input_csv: str, output_dir: str) -> bool:
    """Process URLs from input CSV and save features to output CSV with timestamp"""
    try:
        df = pd.read_csv(input_csv)
        
        if 'url' not in df.columns:
            raise ValueError("Input CSV must contain a 'url' column with URLs")
        
        print(f"Processing {len(df)} URLs...")
        
        # First pass to collect all unique TLDs
        global ENCOUNTERED_TLDS
        for url in df['url']:
            try:
                parsed = urlparse(ensure_url_scheme(url))
                netloc = parsed.netloc.split(':')[0]
                tld = tldextract.extract(netloc).suffix.lower()
                ENCOUNTERED_TLDS.add(tld)
            except:
                continue
        
        # Second pass to extract features with complete TLD knowledge
        features_list = []
        for url in df['url']:
            print(f"Processing: {url}")
            features = extract_url_features(url)
            if features:
                features_list.append(features)
        
        # Combine with original data
        features_df = pd.DataFrame(features_list)
        
        # Ensure is_active is the last column
        cols = [col for col in features_df.columns if col != 'is_active'] + ['is_active']
        features_df = features_df[cols]
        
        result_df = pd.concat([df, features_df], axis=1)
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamped output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"url_features_{timestamp}.csv")
        
        result_df.to_csv(output_file, index=False)
        print(f"Results saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error processing URLs: {e}")
        return False

if __name__ == "__main__":
    # Set your input and output paths here
    input_file = "dataset-cleaning/test_data.csv"  # Your input CSV with 'url' column
    output_dir = "output"  # Directory to save results
    
    # Process the URLs
    success = process_urls(input_file, output_dir)
    if not success:
        print("Failed to process URLs")