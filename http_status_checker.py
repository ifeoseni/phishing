
import os
import re
import pandas as pd
import asyncio
import aiohttp
import aiodns # Required for DNS resolution in asyncio
import ssl
from datetime import datetime
from urllib.parse import urlparse
import tldextract
import logging
import argparse # Added for command-line arguments

# --- Configuration ---
MAX_CONCURRENT_REQUESTS = 200 # Adjust based on system resources and network limits
REQUEST_TIMEOUT = 30 # Seconds
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
# --- End Configuration ---

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# Disable verbose asyncio logging for connection errors
logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)

# Create a default SSL context that doesn't verify certificates
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def ensure_url_scheme(url: str) -> str:
    """Ensure URL has http:// or https:// scheme"""
    if not isinstance(url, str):
        return '' # Handle potential non-string data
    url = url.strip()
    if not url:
        return ''
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return f'http://{url}'
    return url

def get_top_domain(url: str) -> str:
    """Extract the top-level domain using the updated tldextract property."""
    try:
        parsed = urlparse(url)
        domain_part = parsed.netloc.split(':')[0]
        if not domain_part:
             domain_part = parsed.path.split('/')[0].split(':')[0]
        extracted = tldextract.extract(domain_part)
        return extracted.top_domain_under_public_suffix
    except Exception as e:
        log.debug(f"Error extracting domain from {url}: {e}")
        return ""

def was_redirected_outside_domain(original_url: str, history: tuple) -> bool:
    """Check if any redirect in the history went to a different top-level domain."""
    original_domain = get_top_domain(original_url)
    if not original_domain:
        return False

    for resp in history:
        if 300 <= resp.status < 400:
            location_header = resp.headers.get('Location')
            if location_header:
                location_url_with_scheme = ensure_url_scheme(location_header)
                if not urlparse(location_url_with_scheme).netloc:
                    location_url_with_scheme = urlparse(str(resp.url))._replace(path=location_header).geturl()
                redirect_domain = get_top_domain(location_url_with_scheme)
                if redirect_domain and redirect_domain != original_domain:
                    log.debug(f"Redirect detected outside domain: {original_url} -> {location_url_with_scheme} ({original_domain} vs {redirect_domain})")
                    return True
    return False

async def check_url_status_async(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, url: str) -> dict:
    """Asynchronously check HTTP response status and activity for a single URL."""
    result = {
        'url': url,
        'label', label,
        'http_status': 0,
        'is_active': 0,
        'has_redirect': 0,
        'error': ''
    }
    
    url_with_scheme = ensure_url_scheme(url)
    if not url_with_scheme:
        result['error'] = 'Invalid URL format'
        return result

    headers = {'User-Agent': USER_AGENT}
    
    async with semaphore:
        try:
            async with session.get(url_with_scheme, headers=headers, timeout=REQUEST_TIMEOUT, 
                                   allow_redirects=True, ssl=ssl_context) as response:
                result['http_status'] = response.status
                result['is_active'] = 1
                if response.history:
                    result['has_redirect'] = 1 if was_redirected_outside_domain(url_with_scheme, response.history) else 0
                else:
                    result['has_redirect'] = 0
        except asyncio.TimeoutError:
            result['error'] = 'Timeout'
            log.debug(f"Timeout for {url}")
        except aiohttp.ClientConnectorCertificateError as e:
            result['error'] = f'SSL Certificate Error: {e.os_error}'
            log.debug(f"SSL Cert Error for {url}: {e}")
        except aiohttp.ClientConnectorError as e:
            result['error'] = f'Connection Error: {e.os_error}' 
            log.debug(f"Connection Error for {url}: {e}")
        except aiohttp.ClientResponseError as e:
            result['http_status'] = e.status
            result['is_active'] = 1
            result['error'] = f'HTTP Error: {e.status} {e.message}'
            log.debug(f"HTTP Error for {url}: {e.status}")
        except aiohttp.TooManyRedirects:
            result['error'] = 'Too Many Redirects'
            result['is_active'] = 1
            log.debug(f"Too many redirects for {url}")
        except Exception as e:
            result['error'] = f'Unexpected Error: {type(e).__name__} - {e}'
            log.warning(f"Unexpected error for {url}: {type(e).__name__} - {e}")
    return result

# Modified: Accept input_csv and output_dir as arguments
async def process_urls_async(input_csv: str, output_dir: str):
    """Process URLs from input CSV asynchronously and save HTTP status info."""
    try:
        df = pd.read_csv(input_csv, encoding='utf-8') # Added encoding
        if 'url' not in df.columns:
            raise ValueError(f"Input CSV '{input_csv}' must contain a 'url' column")
        
        # urls = df['url'].dropna().unique().tolist()
        url_label_pairs = df[['url', 'label']].dropna().drop_duplicates().values.tolist()
        log.info(f"Processing {len(urls)} unique URLs from '{input_csv}' for HTTP status...")
        
        results = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS, 
            ssl=ssl_context, 
            resolver=aiohttp.AsyncResolver(),
            force_close=True,
            enable_cleanup_closed=True
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [check_url_status_async(session, semaphore, url) for url in urls]
            log.info(f"Starting {len(tasks)} URL checks with concurrency {MAX_CONCURRENT_REQUESTS}...")
            start_time = datetime.now()
            
            completed_results = []
            for i, future in enumerate(asyncio.as_completed(tasks)):
                result = await future
                completed_results.append(result)
                if (i + 1) % 1000 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    log.info(f"Processed {i + 1}/{len(tasks)} URLs from '{input_csv}'... (Rate: {rate:.2f} URLs/sec)")
            
            results = completed_results
            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            log.info(f"Finished processing {len(results)} URLs from '{input_csv}' in {total_time:.2f} seconds.")
            if total_time > 0:
                 log.info(f"Average rate: {len(results) / total_time:.2f} URLs/sec")

        status_df = pd.DataFrame(results)
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Modified: Derive output filename from input filename
        input_basename = os.path.basename(input_csv)
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"http_status_{timestamp_str}_{input_basename}"
        output_file = os.path.join(output_dir, output_filename)
        
        status_df.to_csv(output_file, index=False, encoding='utf-8') # Added encoding
        log.info(f"HTTP status results for '{input_csv}' saved to {output_file}")
        return output_file

    except FileNotFoundError:
        log.error(f"Error: Input file not found at {input_csv}")
        return None
    except ValueError as ve:
        log.error(f"Input Data Error: {ve}")
        return None
    except Exception as e:
        log.exception(f"An unexpected error occurred during processing '{input_csv}': {e}")
        return None

if __name__ == "__main__":
    # Added: Command-line argument parsing
    parser = argparse.ArgumentParser(description="Check HTTP status for URLs in a CSV file.")
    parser.add_argument("--input-file", required=True, help="Path to the input CSV file (must contain a 'url' column).")
    parser.add_argument("--output-dir", required=True, help="Directory to save the output CSV file.")
    args = parser.parse_args()

    # Run the asynchronous processing using arguments
    output_file_path = asyncio.run(process_urls_async(args.input_file, args.output_dir))

    if output_file_path:
        log.info(f"Processing complete. Output saved to: {output_file_path}")
    else:
        log.error(f"Processing failed for input file: {args.input_file}")
        exit(1) # Exit with error code if processing failed

