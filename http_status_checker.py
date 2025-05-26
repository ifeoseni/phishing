
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

# --- Configuration ---
MAX_CONCURRENT_REQUESTS = 200 # Adjust based on system resources and network limits
REQUEST_TIMEOUT = 10 # Seconds
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
# This mimics the verify=False behavior in requests
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
        # Extract domain, handling potential lack of netloc or presence of port
        domain_part = parsed.netloc.split(':')[0]
        if not domain_part:
             # Fallback for URLs like 'example.com' without scheme after ensure_url_scheme
             domain_part = parsed.path.split('/')[0].split(':')[0]

        # Use the recommended property
        extracted = tldextract.extract(domain_part)
        return extracted.top_domain_under_public_suffix
    except Exception as e:
        log.debug(f"Error extracting domain from {url}: {e}")
        return ""

def was_redirected_outside_domain(original_url: str, history: tuple) -> bool:
    """Check if any redirect in the history went to a different top-level domain."""
    original_domain = get_top_domain(original_url)
    if not original_domain:
        return False # Cannot determine original domain

    for resp in history:
        # Check if the status code is a redirect code (3xx)
        if 300 <= resp.status < 400:
            location_header = resp.headers.get('Location')
            if location_header:
                # Ensure the location URL has a scheme for proper parsing
                location_url_with_scheme = ensure_url_scheme(location_header)
                # Handle relative redirects
                if not urlparse(location_url_with_scheme).netloc:
                    location_url_with_scheme = urlparse(resp.url)._replace(path=location_header).geturl()

                redirect_domain = get_top_domain(location_url_with_scheme)
                if redirect_domain and redirect_domain != original_domain:
                    log.debug(f"Redirect detected outside domain: {original_url} -> {location_url_with_scheme} ({original_domain} vs {redirect_domain})")
                    return True
    return False

async def check_url_status_async(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, url: str) -> dict:
    """Asynchronously check HTTP response status and activity for a single URL."""
    result = {
        'url': url,
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
    
    async with semaphore: # Control concurrency
        try:
            # Use GET request directly, allow_redirects=True handles redirects internally
            async with session.get(url_with_scheme, headers=headers, timeout=REQUEST_TIMEOUT, 
                                   allow_redirects=True, ssl=ssl_context) as response:
                
                result['http_status'] = response.status
                result['is_active'] = 1 # If we get a response object, consider it active

                # Check if redirected outside the original domain
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
            # Covers DNS resolution errors, connection refused, etc.
            result['error'] = f'Connection Error: {e.os_error}' 
            log.debug(f"Connection Error for {url}: {e}")
        except aiohttp.ClientResponseError as e:
            # HTTP errors not automatically raised (like 4xx, 5xx)
            result['http_status'] = e.status
            result['is_active'] = 1 # Server responded, even with an error
            result['error'] = f'HTTP Error: {e.status} {e.message}'
            log.debug(f"HTTP Error for {url}: {e.status}")
        except aiohttp.TooManyRedirects:
            result['error'] = 'Too Many Redirects'
            result['is_active'] = 1 # It was active enough to redirect many times
            log.debug(f"Too many redirects for {url}")
        except Exception as e:
            # Catch any other unexpected exceptions
            result['error'] = f'Unexpected Error: {type(e).__name__} - {e}'
            log.warning(f"Unexpected error for {url}: {type(e).__name__} - {e}")
            
    return result

async def process_urls_async(input_csv: str, output_dir: str):
    """Process URLs from input CSV asynchronously and save HTTP status info."""
    try:
        df = pd.read_csv(input_csv)
        if 'url' not in df.columns:
            raise ValueError("Input CSV must contain a 'url' column")
        
        urls = df['url'].dropna().unique().tolist()
        log.info(f"Processing {len(urls)} unique URLs for HTTP status...")
        
        results = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        # Use TCPConnector with limits and specify resolver
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS, 
            ssl=ssl_context, 
            resolver=aiohttp.AsyncResolver(), # Use aiodns resolver
            force_close=True, # Close connections after request
            enable_cleanup_closed=True
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [check_url_status_async(session, semaphore, url) for url in urls]
            
            # Process tasks with progress indication (optional, requires tqdm)
            # try:
            #     from tqdm.asyncio import tqdm_asyncio
            #     results = await tqdm_asyncio.gather(*tasks, desc="Checking URLs")
            # except ImportError:
            #     log.info("tqdm not found, processing without progress bar.")
            #     results = await asyncio.gather(*tasks)

            # Process tasks without tqdm
            log.info(f"Starting {len(tasks)} URL checks with concurrency {MAX_CONCURRENT_REQUESTS}...")
            start_time = datetime.now()
            
            completed_results = []
            for i, future in enumerate(asyncio.as_completed(tasks)):
                result = await future
                completed_results.append(result)
                if (i + 1) % 1000 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    log.info(f"Processed {i + 1}/{len(tasks)} URLs... (Rate: {rate:.2f} URLs/sec)")
            
            results = completed_results # Use the results collected from as_completed
            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            log.info(f"Finished processing {len(results)} URLs in {total_time:.2f} seconds.")
            if total_time > 0:
                 log.info(f"Average rate: {len(results) / total_time:.2f} URLs/sec")

        status_df = pd.DataFrame(results)
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"http_status_{timestamp}.csv")
        
        status_df.to_csv(output_file, index=False)
        log.info(f"HTTP status results saved to {output_file}")
        return output_file

    except FileNotFoundError:
        log.error(f"Error: Input file not found at {input_csv}")
        return None
    except ValueError as ve:
        log.error(f"Input Data Error: {ve}")
        return None
    except Exception as e:
        log.exception(f"An unexpected error occurred during processing: {e}")
        return None

if __name__ == "__main__":
    # Example Usage:
    # Replace with your actual input file path
    # input_file = "dataset-cleaning/remove_duplicate_from_combined_dataset.csv"
    input_file = "dataset-cleaning/remove_duplicate_from_combined_dataset.csv" # Use user's dataset test_data
    output_dir = "http_status"  # Directory to save results


    # Run the asynchronous processing
    output_file_path = asyncio.run(process_urls_async(input_file, output_dir))

    if output_file_path:
        log.info(f"Processing complete. Output saved to: {output_file_path}")
    else:
        log.error("Processing failed.")

