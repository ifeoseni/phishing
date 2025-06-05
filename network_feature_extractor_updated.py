#!/usr/bin/env python3
import asyncio
import aiohttp
import aiodns
import ssl
import socket
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import re
import time
import logging
import os
import sys  # This was missing in the previous version
from concurrent.futures import ThreadPoolExecutor
import whois
from typing import Dict, Any, Optional, Tuple, List
import argparse

# --- Configuration ---
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
            extracted_direct = tldextract.extract(url)
            if extracted_direct.domain and extracted_direct.suffix:
                return extracted_direct.registered_domain
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
        try:
            domain_part = url.split('/')[0] if '/' in url else url
            return domain_part.split(':')[0]
        except Exception:
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
    
    if not domain or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
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
            logger.warning(f"DNS query error for {qname} {rdtype}: {type(e).__name__} - {e}")
            return None

    tasks = {
        'a': query_dns(domain, 'A'),
        'mx': query_dns(domain, 'MX'),
        'txt': query_dns(domain, 'TXT'),
        'ns': query_dns(domain, 'NS'),
        'dkim': query_dns(f'default._domainkey.{domain}', 'TXT'),
        'dmarc': query_dns(f'_dmarc.{domain}', 'TXT'),
        'cname': query_dns(domain, 'CNAME'),
    }
    
    responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    if responses[0] and not isinstance(responses[0], Exception):
        results.update({'dns_a_presence': 1, 'dns_a_count': len(responses[0])})
    if responses[1] and not isinstance(responses[1], Exception):
        results.update({'dns_mx_presence': 1, 'dns_mx_count': len(responses[1])})
    if responses[2] and not isinstance(responses[2], Exception):
        results.update({'dns_txt_presence': 1, 'dns_txt_count': len(responses[2])})
        spf_count = sum(1 for r in responses[2] if 'v=spf1' in str(r.text).lower())
        results.update({'dns_spf_presence': 1 if spf_count > 0 else 0, 'dns_spf_count': spf_count})
    if responses[3] and not isinstance(responses[3], Exception):
        results.update({'dns_ns_presence': 1, 'dns_ns_count': len(responses[3])})
    if responses[4] and not isinstance(responses[4], Exception):
        results.update({'dns_dkim_presence': 1, 'dns_dkim_count': len(responses[4])})
    if responses[5] and not isinstance(responses[5], Exception):
        dmarc_count = sum(1 for r in responses[5] if 'v=dmarc1' in str(r.text).lower())
        results.update({'dns_dmarc_presence': 1 if dmarc_count > 0 else 0, 'dns_dmarc_count': dmarc_count})
    if responses[6] and not isinstance(responses[6], Exception):
        results.update({'dns_cname_presence': 1, 'dns_cname_count': len(responses[6])})

    return results

async def fetch_ssl_cert_async(url: str) -> Dict[str, Any]:
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

        if parsed.scheme != 'https' or not hostname or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return cert_features

        ssl_context = ssl.create_default_context()
        conn = asyncio.open_connection(hostname, port, ssl=ssl_context)
        reader, writer = await asyncio.wait_for(conn, timeout=REQUEST_TIMEOUT)

        cert = writer.get_extra_info('peercert')
        if cert:
            cert_features['has_ssl'] = 1
            
            expire_date_str = cert.get('notAfter')
            if expire_date_str:
                try:
                    expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                    expire_date = expire_date.replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    expiry_days = (expire_date - now_utc).days
                    cert_features['ssl_expiry_days'] = expiry_days
                    if expiry_days < 0:
                        cert_features['has_expired_ssl'] = 1
                except ValueError as ve:
                    logger.warning(f"Could not parse SSL expiry date '{expire_date_str}' for {url}: {ve}")
                    pass

            issuer = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))
            if issuer == subject:
                cert_features['has_self_signed_ssl'] = 1

        writer.close()
        await writer.wait_closed()

    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL Verification Error for {url}: {e}")
        cert_features.update({
            'has_ssl': 1,
            'has_ssl_errors': 1,
            'has_mismatched_ssl': 1 if "hostname mismatch" in str(e) else 0,
            'has_expired_ssl': 1 if "certificate has expired" in str(e) else 0,
            'has_self_signed_ssl': 1 if "self-signed" in str(e) else 0,
        })
    except ssl.SSLError as e:
        logger.warning(f"SSL Error for {url}: {e}")
        cert_features['has_ssl_errors'] = 1
    except asyncio.TimeoutError:
         logger.warning(f"SSL connection timeout for {url}")
         cert_features['has_ssl_errors'] = 1
    except OSError as e:
         logger.warning(f"SSL OS Error (e.g., connection refused) for {url}: {e}")
         cert_features['has_ssl_errors'] = 1
    except Exception as e:
        logger.warning(f"Unexpected SSL check error for {url}: {type(e).__name__} - {e}")
        cert_features['has_ssl_errors'] = 1

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
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        async with session.get(url_with_scheme, timeout=REQUEST_TIMEOUT, headers=headers, ssl=ssl_context, allow_redirects=True) as response:
            features['response_time'] = time.time() - start_time
            features['redirect_count'] = len(response.history)
            final_url = str(response.url)
            features['final_url_diff'] = 1 if final_url != url_with_scheme else 0
            
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
                if header in response.headers or header.title() in response.headers:
                    features[feature] = 1
            
            if 'Set-Cookie' in response.headers:
                features['has_cookie'] = 1
                cookies = response.headers.getall('Set-Cookie', [])
                for cookie_str in cookies:
                    if 'httponly' in cookie_str.lower():
                        features['has_http_only_cookie'] = 1
                    if 'secure' in cookie_str.lower():
                        features['has_secure_cookie'] = 1
                    if features['has_http_only_cookie'] and features['has_secure_cookie']:
                        break
            
            if 'Content-Length' in response.headers:
                try:
                    features['content_length'] = int(response.headers['Content-Length'])
                except (ValueError, TypeError):
                    pass
            
            content_type = response.headers.get('Content-Type', '').lower()
            if response.status == 200 and 'text/html' in content_type:
                try:
                    html_content = await response.content.read(MAX_HTML_SIZE)
                    encoding = response.get_encoding() or 'utf-8'
                    html_text = html_content.decode(encoding, errors='replace')
                    
                    try:
                        soup = BeautifulSoup(html_text, 'lxml')
                    except ImportError:
                        soup = BeautifulSoup(html_text, 'html.parser')
                    except Exception as parse_err:
                         logger.warning(f"HTML parsing failed for {url} with parser: {parse_err}")
                         soup = None

                    if soup:
                        title_tag = soup.find('title')
                        if title_tag and title_tag.string:
                            title_text = title_tag.string.strip()
                            features.update({'has_title': 1, 'title_length': len(title_text)})
                        
                        features.update({
                            'num_iframes': len(soup.find_all('iframe')),
                            'has_iframe': 1 if soup.find('iframe') else 0,
                            'num_scripts': len(soup.find_all('script')),
                            'has_javascript': 1 if soup.find('script') else 0,
                            'num_links': len(soup.find_all('a', href=True)),
                            'has_link': 1 if soup.find('a', href=True) else 0,
                            'num_a_tags': len(soup.find_all('a')),
                            'num_images': len(soup.find_all('img')),
                            'has_image': 1 if soup.find('img') else 0,
                            'has_favicon': 1 if soup.find('link', rel=re.compile(r'icon|shortcut icon', re.I)) else 0,
                        })
                        
                        has_text = 1 if soup.find('input', {'type': 'text'}) else 0
                        has_pass = 1 if soup.find('input', {'type': 'password'}) else 0
                        has_submit = 1 if soup.find('input', {'type': 'submit'}) or soup.find('button', {'type': 'submit'}) else 0
                        
                        features.update({
                            'has_text_input': has_text,
                            'has_password_input': has_pass,
                            'has_submit': has_submit,
                            'has_button': 1 if soup.find('button') else 0,
                        })
                    
                except UnicodeDecodeError as ude:
                    logger.warning(f"Unicode decode error for {url} with encoding {encoding}: {ude}")
                except Exception as e:
                    logger.warning(f"HTML processing error for {url}: {type(e).__name__} - {e}")
            elif response.status != 200:
                 logger.info(f"Skipping HTML parse for {url} due to status code: {response.status}")
            elif 'text/html' not in content_type:
                 logger.info(f"Skipping HTML parse for {url} due to content type: {content_type}")

    except asyncio.TimeoutError:
        logger.warning(f"Timeout fetching HTML features for {url}")
    except aiohttp.ClientError as e:
        logger.warning(f"ClientError fetching HTML for {url}: {type(e).__name__} - {e}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching HTML features for {url}: {type(e).__name__} - {e}")

    return features

def fetch_whois_sync(domain: str) -> Tuple[Optional[int], Optional[int]]:
    """Synchronous WHOIS lookup."""
    age_days = None
    expiry_days = None
    
    if not domain or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return age_days, expiry_days

    try:
        w = whois.whois(domain)
        
        def get_earliest_date(dates):
            if not dates:
                return None
            if isinstance(dates, list):
                valid_dates = [d for d in dates if isinstance(d, datetime)]
                return min(valid_dates) if valid_dates else None
            return dates if isinstance(dates, datetime) else None

        creation_date = get_earliest_date(w.creation_date)
        expiration_date = get_earliest_date(w.expiration_date)
        
        now_utc = datetime.now(timezone.utc)

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            if creation_date <= now_utc:
                 age_days = (now_utc - creation_date).days
            else: 
                 logger.warning(f"WHOIS creation date in future for {domain}: {creation_date}")
        
        if expiration_date:
            if expiration_date.tzinfo is None:
                expiration_date = expiration_date.replace(tzinfo=timezone.utc)
            expiry_days = (expiration_date - now_utc).days
                
    except whois.parser.PywhoisError as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
    except Exception as e:
        logger.error(f"Unexpected WHOIS error for {domain}: {type(e).__name__} - {e}")

    return age_days, expiry_days

async def fetch_whois_async(domain: str, executor: ThreadPoolExecutor) -> Tuple[Optional[int], Optional[int]]:
    """Run WHOIS lookup in thread pool."""
    if not domain:
        return None, None
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(executor, fetch_whois_sync, domain)
        return result
    except Exception as e:
        logger.error(f"Error running WHOIS task for {domain} in executor: {e}")
        return None, None

async def process_single_url(url_data: pd.Series, session: aiohttp.ClientSession, 
                           resolver: aiodns.DNSResolver, executor: ThreadPoolExecutor, 
                           semaphore: asyncio.Semaphore):
    """Processes a single URL row to extract all network features."""
    async with semaphore:
        url = url_data.get('url', '')
        
        # Initialize features with defaults
        features = {**NETWORK_FEATURE_DEFAULTS}
        
        if not url or not isinstance(url, str):
            logger.warning(f"Skipping invalid URL data: {url_data}")
            return features

        registered_domain = get_registered_domain(url)
        
        # Prepare tasks
        tasks_to_run = {}
        
        if registered_domain and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', registered_domain):
            tasks_to_run['dns'] = fetch_dns_records_async(registered_domain, resolver)
            tasks_to_run['ssl'] = fetch_ssl_cert_async(url)
            tasks_to_run['whois'] = fetch_whois_async(registered_domain, executor)
        else:
            logger.info(f"Skipping DNS/SSL/WHOIS for non-domain or IP: {url}")
        
        tasks_to_run['html'] = fetch_html_features_async(url, session)
        
        if tasks_to_run:
            task_keys = list(tasks_to_run.keys())
            results = await asyncio.gather(*tasks_to_run.values(), return_exceptions=True)
            
            for i, key in enumerate(task_keys):
                res = results[i]
                if isinstance(res, Exception):
                    logger.error(f"Error in task '{key}' for {url}: {type(res).__name__} - {res}")
                elif key == 'dns':
                    features.update(res)
                elif key == 'ssl':
                    features.update(res)
                elif key == 'whois':
                    if isinstance(res, tuple) and len(res) == 2:
                        age, expiry = res
                        features['domain_age_days'] = age
                        features['time_to_expiration'] = expiry
                    else:
                        logger.warning(f"Unexpected WHOIS result format for {url}: {res}")
                elif key == 'html':
                    features.update(res)
        
        return features

async def run_extraction(input_file: str, output_file: str):
    """Main async function to handle file reading, processing, and writing."""
    logger.info(f"Starting network feature extraction for {input_file}...")
    start_time = time.time()

    try:
        if not os.path.exists(input_file):
            logger.error(f"Input file not found: {input_file}")
            return
        
        # Read all columns from input file
        df = pd.read_csv(input_file)
        logger.info(f"Read {len(df)} rows from {input_file}")
        
        # Basic cleaning
        df = df.dropna(subset=['url'])
        df['url'] = df['url'].astype(str)
        logger.info(f"Processing {len(df)} URLs after cleaning.")

    except Exception as e:
        logger.error(f"Error reading input CSV {input_file}: {type(e).__name__} - {e}")
        return

    if df.empty:
        logger.warning(f"Input file {input_file} is empty or contains no valid URLs.")
        return
        
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    resolver = aiodns.DNSResolver(timeout=REQUEST_TIMEOUT)
    executor = ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 1) + 4))
    
    conn = aiohttp.TCPConnector(
        limit=CONCURRENCY_LIMIT,
        limit_per_host=20,
        enable_cleanup_closed=True,
        ssl=False,
    )
    
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [
            process_single_url(row, session, resolver, executor, semaphore)
            for _, row in df.iterrows()
        ]
        
        logger.info(f"Created {len(tasks)} tasks. Running with concurrency limit {CONCURRENCY_LIMIT}...")
        
        results_list = []
        completed_count = 0
        total_tasks = len(tasks)
        progress_interval = max(1, min(total_tasks // 20, 1000))
        
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                if result:
                    results_list.append(result)
            except Exception as e:
                logger.error(f"Unhandled exception during task execution: {type(e).__name__} - {e}")
            
            completed_count += 1
            if completed_count % progress_interval == 0 or completed_count == total_tasks:
                elapsed_time = time.time() - start_time
                rate = completed_count / elapsed_time if elapsed_time > 0 else 0
                logger.info(f"Progress: {completed_count}/{total_tasks} ({completed_count/total_tasks:.1%}) - {rate:.2f} URLs/sec")

    logger.info("All tasks completed. Combining results...")
    
    if not results_list:
        logger.warning("No results were generated. Check logs for errors.")
        executor.shutdown(wait=False)
        return
    
    # Create DataFrame from network features
    network_df = pd.DataFrame(results_list)
    
    # Merge network features with original DataFrame by index
    final_df = df.join(network_df)
    
    # Fill NaN values in network feature columns with appropriate defaults
    for col, default_val in NETWORK_FEATURE_DEFAULTS.items():
        if col in final_df.columns:
            if pd.api.types.is_numeric_dtype(final_df[col]):
                final_df[col] = final_df[col].fillna(default_val if default_val is not None else 0)

    # Save output
    try:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        final_df.to_csv(output_file, index=False)
        logger.info(f"Successfully saved {len(final_df)} rows to {output_file}")
    except Exception as e:
        logger.error(f"Error saving output to {output_file}: {type(e).__name__} - {e}")
    
    executor.shutdown(wait=True)
    logger.info(f"Processing completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract network features for URLs in a CSV file.")
    parser.add_argument("--input-file", required=True, help="Path to the input CSV file containing URLs.")
    parser.add_argument("--output-file", required=True, help="Path to save the output CSV file with network features.")
    args = parser.parse_args()

    # Dependency check for whois
    try:
        import whois
    except ImportError:
        logger.error("python-whois library not found. Please install it manually: pip install python-whois")
        sys.exit(1)
            
    asyncio.run(run_extraction(args.input_file, args.output_file))