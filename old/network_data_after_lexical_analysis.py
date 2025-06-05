import asyncio
import aiohttp
import aiodns
import ssl
import socket
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
import re
import time
import logging
import os
from concurrent.futures import ThreadPoolExecutor
import whois
from typing import Dict, Any, Optional, Tuple, List

# --- Configuration ---
INPUT_CSV = "input_lexical_http.csv"  # Contains URL and lexical features
OUTPUT_CSV = "output_network_features.csv"
CONCURRENCY_LIMIT = 100
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
MAX_HTML_SIZE = 5 * 1024 * 1024  # 5 MB
WHOIS_TIMEOUT = 10

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Network Feature Defaults ---
NETWORK_FEATURE_DEFAULTS = {
    # DNS Features
    'dns_a_presence': 0, 'dns_a_count': 0,
    'dns_mx_presence': 0, 'dns_mx_count': 0,
    'dns_txt_presence': 0, 'dns_txt_count': 0,
    'dns_ns_presence': 0, 'dns_ns_count': 0,
    'dns_spf_presence': 0, 'dns_spf_count': 0,
    'dns_dkim_presence': 0, 'dns_dkim_count': 0,
    'dns_dmarc_presence': 0, 'dns_dmarc_count': 0,
    'dns_cname_presence': 0, 'dns_cname_count': 0,
    
    # SSL Features
    'has_ssl': 0, 'ssl_expiry_days': None,
    'has_ssl_errors': 0, 'has_mismatched_ssl': 0,
    'has_expired_ssl': 0, 'has_self_signed_ssl': 0,
    
    # WHOIS Features
    'domain_age_days': None, 'time_to_expiration': None,
    
    # HTTP/HTML Features
    'redirect_count': 0, 'final_url_diff': 0,
    'response_time': None, 'content_length': None,
    'has_title': 0, 'title_length': 0,
    'has_iframe': 0, 'num_iframes': 0,
    'has_text_input': 0, 'has_password_input': 0,
    'has_button': 0, 'has_image': 0,
    'has_submit': 0, 'has_link': 0,
    'num_links': 0, 'num_images': 0,
    'num_scripts': 0, 'has_javascript': 0,
    'has_favicon': 0, 'num_a_tags': 0,
    
    # Security Headers
    'has_xss_protection': 0, 'has_csp': 0,
    'has_hsts': 0, 'has_x_frame_options': 0,
    'has_x_content_type_options': 0,
    'has_referrer_policy': 0, 'has_feature_policy': 0,
    
    # Cookie Features
    'has_cookie': 0, 'has_http_only_cookie': 0,
    'has_secure_cookie': 0,
}

# --- Helper Functions ---
def ensure_url_scheme(url: str) -> str:
    """Ensure URL has http:// or https:// scheme."""
    if not isinstance(url, str):
        return ""
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return f'http://{url}'
    return url

def get_registered_domain(url: str) -> Optional[str]:
    """Extract the registered domain from a URL."""
    try:
        if not isinstance(url, str) or not url.strip():
            return None
        parsed = urlparse(ensure_url_scheme(url))
        netloc = parsed.netloc
        if not netloc:
            return None
        extracted = tldextract.extract(netloc)
        if extracted.domain and extracted.suffix:
            return extracted.registered_domain
        ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', netloc.split(":")[0])
        if ip_match:
            return ip_match.group(1)
        return netloc.split(":")[0] if netloc else None
    except Exception as e:
        logger.warning(f"TLDExtract error for {url}: {e}")
        return None

# --- Network Feature Extraction Functions ---
async def fetch_dns_records_async(domain: str, resolver: aiodns.DNSResolver) -> Dict[str, Any]:
    """Fetch DNS records asynchronously."""
    results = {
        'dns_a_presence': 0, 'dns_a_count': 0,
        'dns_mx_presence': 0, 'dns_mx_count': 0,
        'dns_txt_presence': 0, 'dns_txt_count': 0,
        'dns_ns_presence': 0, 'dns_ns_count': 0,
        'dns_spf_presence': 0, 'dns_spf_count': 0,
        'dns_dkim_presence': 0, 'dns_dkim_count': 0,
        'dns_dmarc_presence': 0, 'dns_dmarc_count': 0,
        'dns_cname_presence': 0, 'dns_cname_count': 0,
    }
    
    if not domain:
        return results

    async def query_dns(qname, rdtype):
        try:
            return await resolver.query(qname, rdtype)
        except (aiodns.error.DNXDomain, aiodns.error.DNoData):
            return None
        except asyncio.TimeoutError:
            logger.warning(f"DNS query timeout for {qname} {rdtype}")
            return None
        except Exception as e:
            logger.warning(f"DNS query error for {qname} {rdtype}: {e}")
            return None

    registered_domain = get_registered_domain(domain)
    if not registered_domain:
        logger.warning(f"Could not extract registered domain for DNS checks on: {domain}")
        return results

    # DNS queries
    tasks = {
        'a': query_dns(registered_domain, 'A'),
        'mx': query_dns(registered_domain, 'MX'),
        'txt': query_dns(registered_domain, 'TXT'),
        'ns': query_dns(registered_domain, 'NS'),
        'dkim': query_dns(f'default._domainkey.{registered_domain}', 'TXT'),
        'dmarc': query_dns(f'_dmarc.{registered_domain}', 'TXT'),
    }
    
    responses = await asyncio.gather(*tasks.values())
    
    # Process responses
    if responses[0]:  # A records
        results.update({'dns_a_presence': 1, 'dns_a_count': len(responses[0])})
    if responses[1]:  # MX records
        results.update({'dns_mx_presence': 1, 'dns_mx_count': len(responses[1])})
    if responses[2]:  # TXT records
        results.update({'dns_txt_presence': 1, 'dns_txt_count': len(responses[2])})
        spf_count = sum(1 for r in responses[2] if 'v=spf1' in str(r).lower())
        results.update({'dns_spf_presence': 1 if spf_count > 0 else 0, 'dns_spf_count': spf_count})
    if responses[3]:  # NS records
        results.update({'dns_ns_presence': 1, 'dns_ns_count': len(responses[3])})
    if responses[4]:  # DKIM records
        results.update({'dns_dkim_presence': 1, 'dns_dkim_count': len(responses[4])})
    if responses[5]:  # DMARC records
        dmarc_count = sum(1 for r in responses[5] if 'v=dmarc1' in str(r).lower())
        results.update({'dns_dmarc_presence': 1 if dmarc_count > 0 else 0, 'dns_dmarc_count': dmarc_count})

    return results

async def fetch_ssl_cert_async(url: str) -> Tuple[int, Optional[int], Dict[str, Any]]:
    """Check SSL certificate and return features."""
    cert_features = {
        'has_ssl': 0,
        'ssl_expiry_days': None,
        'has_ssl_errors': 0,
        'has_mismatched_ssl': 0,
        'has_expired_ssl': 0,
        'has_self_signed_ssl': 0,
    }
    
    try:
        parsed = urlparse(ensure_url_scheme(url))
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if port != 443:
            return cert_features

        ssl_context = ssl.create_default_context()
        conn = asyncio.open_connection(hostname, port, ssl=ssl_context)
        reader, writer = await asyncio.wait_for(conn, timeout=REQUEST_TIMEOUT)

        cert = writer.get_extra_info('peercert')
        if cert:
            cert_features['has_ssl'] = 1
            
            # Check expiry
            expire_date_str = cert.get('notAfter')
            if expire_date_str:
                try:
                    expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
                    now_utc = datetime.now(datetime.timezone.utc)
                    expiry_days = (expire_date - now_utc).days
                    cert_features['ssl_expiry_days'] = expiry_days
                    if expiry_days < 0:
                        cert_features['has_expired_ssl'] = 1
                except ValueError:
                    pass

            # Check self-signed
            issuer = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))
            if issuer == subject:
                cert_features['has_self_signed_ssl'] = 1

        writer.close()
        await writer.wait_closed()

    except ssl.SSLCertVerificationError as e:
        cert_features.update({
            'has_ssl': 1,
            'has_ssl_errors': 1,
            'has_mismatched_ssl': 1 if "hostname mismatch" in str(e) else 0,
            'has_expired_ssl': 1 if "certificate has expired" in str(e) else 0,
            'has_self_signed_ssl': 1 if "self-signed" in str(e) else 0,
        })
    except Exception as e:
        logger.warning(f"SSL check error for {url}: {e}")

    return cert_features

async def fetch_html_features_async(url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """Fetch and parse HTML to extract features."""
    features = {
        'redirect_count': 0, 'final_url_diff': 0,
        'response_time': None, 'content_length': None,
        'has_title': 0, 'title_length': 0,
        'has_iframe': 0, 'num_iframes': 0,
        'has_text_input': 0, 'has_password_input': 0,
        'has_button': 0, 'has_image': 0,
        'has_submit': 0, 'has_link': 0,
        'num_links': 0, 'num_images': 0,
        'num_scripts': 0, 'has_javascript': 0,
        'has_favicon': 0, 'num_a_tags': 0,
        'has_xss_protection': 0, 'has_csp': 0,
        'has_hsts': 0, 'has_x_frame_options': 0,
        'has_x_content_type_options': 0,
        'has_referrer_policy': 0, 'has_feature_policy': 0,
        'has_cookie': 0, 'has_http_only_cookie': 0,
        'has_secure_cookie': 0,
    }

    try:
        start_time = time.time()
        url_with_scheme = ensure_url_scheme(url)
        headers = {'User-Agent': USER_AGENT}
        
        async with session.get(url_with_scheme, timeout=REQUEST_TIMEOUT, headers=headers, ssl=False, allow_redirects=True) as response:
            features['response_time'] = time.time() - start_time
            features['redirect_count'] = len(response.history)
            features['final_url_diff'] = 1 if str(response.url) != url_with_scheme else 0
            
            # Security headers
            security_headers = {
                'x-xss-protection': 'has_xss_protection',
                'content-security-policy': 'has_csp',
                'strict-transport-security': 'has_hsts',
                'x-frame-options': 'has_x_frame_options',
                'x-content-type-options': 'has_x_content_type_options',
                'referrer-policy': 'has_referrer_policy',
                'feature-policy': 'has_feature_policy'
            }
            
            for header, feature in security_headers.items():
                if header in response.headers:
                    features[feature] = 1
            
            # Cookies
            if 'set-cookie' in response.headers:
                features['has_cookie'] = 1
                cookies = response.headers.getall('set-cookie', [])
                for cookie in cookies:
                    if 'HttpOnly' in cookie:
                        features['has_http_only_cookie'] = 1
                    if 'Secure' in cookie:
                        features['has_secure_cookie'] = 1
            
            # Content length
            if 'content-length' in response.headers:
                try:
                    features['content_length'] = int(response.headers['content-length'])
                except ValueError:
                    pass
            
            # HTML parsing only for successful responses
            if response.status == 200 and 'text/html' in response.headers.get('Content-Type', '').lower():
                try:
                    html_content = await response.content.read(MAX_HTML_SIZE)
                    html_text = html_content.decode(response.get_encoding() or 'utf-8', errors='replace')
                    
                    # Parse with BeautifulSoup
                    try:
                        soup = BeautifulSoup(html_text, 'lxml' if 'lxml' in globals() else 'html.parser')
                    except Exception:
                        soup = BeautifulSoup(html_text, 'html.parser')
                    
                    # Extract features from HTML
                    title_tag = soup.find('title')
                    if title_tag and title_tag.string:
                        title_text = title_tag.string.strip()
                        features.update({'has_title': 1, 'title_length': len(title_text)})
                    
                    # Count elements
                    features.update({
                        'num_iframes': len(soup.find_all('iframe')),
                        'has_iframe': 1 if soup.find('iframe') else 0,
                        'num_scripts': len(soup.find_all('script')),
                        'has_javascript': 1 if soup.find('script') else 0,
                        'num_links': len(soup.find_all('a')),
                        'has_link': 1 if soup.find('a') else 0,
                        'num_a_tags': len(soup.find_all('a')),
                        'num_images': len(soup.find_all('img')),
                        'has_image': 1 if soup.find('img') else 0,
                        'has_favicon': 1 if soup.find('link', rel=re.compile(r'icon|shortcut icon', re.I)) else 0,
                    })
                    
                    # Form elements
                    has_text = 1 if soup.find('input', {'type': 'text'}) else 0
                    has_pass = 1 if soup.find('input', {'type': 'password'}) else 0
                    has_submit = 1 if soup.find('input', {'type': 'submit'}) or soup.find('button', {'type': 'submit'}) else 0
                    
                    features.update({
                        'has_text_input': has_text,
                        'has_password_input': has_pass,
                        'has_submit': has_submit,
                        'has_button': 1 if soup.find('button') else 0,
                    })
                    
                except Exception as e:
                    logger.warning(f"HTML parsing error for {url}: {e}")

    except Exception as e:
        logger.warning(f"Error fetching HTML features for {url}: {e}")

    return features

def fetch_whois_sync(domain: str) -> Tuple[Optional[int], Optional[int]]:
    """Synchronous WHOIS lookup."""
    age_days = None
    expiry_days = None
    
    if not domain:
        return age_days, expiry_days

    try:
        w = whois.whois(domain)
        
        if w.creation_date:
            creation_date = min(w.creation_date) if isinstance(w.creation_date, list) else w.creation_date
            if creation_date:
                now_utc = datetime.now(datetime.timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
                age_days = (now_utc - creation_date).days
        
        if w.expiration_date:
            expiry_date = min(w.expiration_date) if isinstance(w.expiration_date, list) else w.expiration_date
            if expiry_date:
                now_utc = datetime.now(datetime.timezone.utc)
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
                expiry_days = (expiry_date - now_utc).days
                
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    return age_days, expiry_days

async def fetch_whois_async(domain: str, executor: ThreadPoolExecutor) -> Tuple[Optional[int], Optional[int]]:
    """Run WHOIS lookup in thread pool."""
    if not domain:
        return None, None
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(executor, fetch_whois_sync, domain)
    except Exception as e:
        logger.error(f"Error running WHOIS for {domain}: {e}")
        return None, None

async def process_single_url(url_data: pd.Series, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, executor: ThreadPoolExecutor, semaphore: asyncio.Semaphore):
    """Process a single URL to extract network features."""
    async with semaphore:
        url = url_data.get('url')
        http_status = url_data.get('http_status')
        
        features = NETWORK_FEATURE_DEFAULTS.copy()
        features['original_url'] = url
        
        if not url or pd.isna(url):
            logger.warning("Skipping row with missing URL")
            return features

        registered_domain = get_registered_domain(url)
        
        # Run tasks concurrently
        tasks = {}
        
        if registered_domain and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', registered_domain):
            tasks['dns'] = fetch_dns_records_async(registered_domain, resolver)
            tasks['ssl'] = fetch_ssl_cert_async(url)
            tasks['whois'] = fetch_whois_async(registered_domain, executor)
        
        if http_status == 200:
            tasks['html'] = fetch_html_features_async(url, session)
        
        if tasks:
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            
            for i, (key, res) in enumerate(zip(tasks.keys(), results)):
                if isinstance(res, Exception):
                    logger.error(f"Error in task '{key}' for {url}: {res}")
                elif key == 'dns':
                    features.update(res)
                elif key == 'ssl':
                    features.update(res)
                elif key == 'whois':
                    age, expiry = res
                    features['domain_age_days'] = age
                    features['time_to_expiration'] = expiry
                elif key == 'html':
                    features.update(res)
        
        return features

async def main():
    logger.info("Starting network feature extraction...")
    start_time = time.time()

    try:
        if not os.path.exists(INPUT_CSV):
            logger.error(f"Input file not found: {INPUT_CSV}")
            return
        
        df = pd.read_csv(INPUT_CSV)
        logger.info(f"Read {len(df)} rows from {INPUT_CSV}")
        
        required_cols = ['url', 'http_status']
        if not all(col in df.columns for col in required_cols):
            raise ValueError(f"Input CSV must contain columns: {required_cols}")
        
        df = df.dropna(subset=['url'])
        df['url'] = df['url'].astype(str)
        df['http_status'] = pd.to_numeric(df['http_status'], errors='coerce').fillna(0).astype(int)
        logger.info(f"Processing {len(df)} rows after cleaning.")

    except Exception as e:
        logger.error(f"Error reading input CSV: {e}")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    resolver = aiodns.DNSResolver(timeout=REQUEST_TIMEOUT)
    executor = ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 1) + 4))
    
    conn = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=20,
        enable_cleanup_closed=True,
    )
    
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [
            process_single_url(row, session, resolver, executor, semaphore)
            for _, row in df.iterrows()
        ]
        
        logger.info(f"Created {len(tasks)} tasks. Running with concurrency limit {CONCURRENCY_LIMIT}...")
        
        results = []
        completed = 0
        total = len(tasks)
        progress_interval = max(1, min(total // 20, 1000))
        
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                results.append(result)
            except Exception as e:
                logger.error(f"Unhandled exception: {e}")
                results.append({'original_url': 'error', **NETWORK_FEATURE_DEFAULTS})
            
            completed += 1
            if completed % progress_interval == 0 or completed == total:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                logger.info(f"Progress: {completed}/{total} ({completed/total:.1%}) - {rate:.2f} URLs/sec")

    logger.info("All tasks completed. Combining results...")
    
    if not results:
        logger.warning("No results were generated")
        return
    
    network_df = pd.DataFrame([r for r in results if r is not None])
    final_df = pd.merge(df, network_df, left_on='url', right_on='original_url', how='left')
    
    if 'original_url' in final_df.columns:
        final_df = final_df.drop(columns=['original_url'])
    
    # Save output
    try:
        os.makedirs(os.path.dirname(OUTPUT_CSV) or '.', exist_ok=True)
        final_df.to_csv(OUTPUT_CSV, index=False)
        logger.info(f"Saved {len(final_df)} rows to {OUTPUT_CSV}")
    except Exception as e:
        logger.error(f"Error saving output: {e}")
    
    executor.shutdown(wait=True)
    logger.info(f"Processing completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    try:
        import whois
    except ImportError:
        logger.info("Installing python-whois...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-whois"])
    
    asyncio.run(main())