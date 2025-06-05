import os
import re
import pandas as pd
import asyncio
import aiohttp
import aiodns
import ssl
from datetime import datetime
from urllib.parse import urlparse
import tldextract
import logging
import argparse

# --- Configuration ---
MAX_CONCURRENT_REQUESTS = 200
REQUEST_TIMEOUT = 30
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
# --- End Configuration ---

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# Disable verbose logging
logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)

# SSL context
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def ensure_url_scheme(url: str) -> str:
    if not isinstance(url, str):
        return ''
    url = url.strip()
    if not url:
        return ''
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return f'http://{url}'
    return url

def get_top_domain(url: str) -> str:
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

async def process_urls_async(input_csv: str, output_dir: str):
    try:
        # Read input CSV preserving all columns
        df_original = pd.read_csv(input_csv, encoding='utf-8')
        if 'url' not in df_original.columns:
            raise ValueError(f"Input CSV '{input_csv}' must contain a 'url' column")

        has_label = 'label' in df_original.columns
        log.info(f"Input file has {len(df_original)} rows and {'includes' if has_label else 'does not include'} a label column")
        
        # Get unique URLs for processing (we'll process each URL only once)
        unique_urls = df_original['url'].dropna().unique()
        log.info(f"Found {len(unique_urls)} unique URLs to process")

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
            tasks = [check_url_status_async(session, semaphore, url) for url in unique_urls]
            log.info(f"Starting {len(tasks)} URL checks with concurrency {MAX_CONCURRENT_REQUESTS}...")
            start_time = datetime.now()

            for i, future in enumerate(asyncio.as_completed(tasks)):
                result = await future
                results.append(result)
                if (i + 1) % 1000 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    log.info(f"Processed {i + 1}/{len(tasks)} URLs... (Rate: {rate:.2f} URLs/sec)")

            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            log.info(f"Finished processing {len(results)} URLs in {total_seconds:.2f} seconds.")

        # Create DataFrame from results
        status_df = pd.DataFrame(results)
        log.info(f"Created status DataFrame with {len(status_df)} rows and columns: {list(status_df.columns)}")

        # Merge results back with original DataFrame using left join to preserve all original rows
        df_merged = df_original.merge(status_df, on='url', how='left')
        
        log.info(f"After merge: {len(df_merged)} rows with columns: {list(df_merged.columns)}")
        
        # Verify that label column is preserved if it existed
        if has_label and 'label' not in df_merged.columns:
            log.error("CRITICAL: Label column was lost during merge!")
            # Emergency fallback - reconstruct the merge manually
            df_merged = df_original.copy()
            status_dict = status_df.set_index('url').to_dict('index')
            
            for idx, row in df_merged.iterrows():
                url = row['url']
                if pd.notna(url) and url in status_dict:
                    for col, val in status_dict[url].items():
                        if col != 'url':  # Don't overwrite URL column
                            df_merged.at[idx, col] = val
                else:
                    # Fill with default values for URLs that weren't processed
                    df_merged.at[idx, 'http_status'] = 0
                    df_merged.at[idx, 'is_active'] = 0
                    df_merged.at[idx, 'has_redirect'] = 0
                    df_merged.at[idx, 'error'] = 'Not processed'
            
            log.info(f"Manual merge completed. Final columns: {list(df_merged.columns)}")

        # Final verification
        if has_label:
            if 'label' in df_merged.columns:
                log.info(f"✓ Label column preserved successfully with {df_merged['label'].notna().sum()} non-null values")
            else:
                log.error("✗ FAILED: Label column is missing from final output!")
        
        # Save results
        os.makedirs(output_dir, exist_ok=True)
        input_basename = os.path.basename(input_csv)
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"http_status_{timestamp_str}_{input_basename}"
        output_file = os.path.join(output_dir, output_filename)

        df_merged.to_csv(output_file, index=False, encoding='utf-8')
        log.info(f"HTTP status results saved to {output_file}")

        # Final verification log
        log.info(f"Final output - Shape: {df_merged.shape}, Columns: {list(df_merged.columns)}")
        if len(df_merged) > 0:
            sample_row = df_merged.iloc[0]
            log.info(f"Sample row: url={sample_row.get('url', 'N/A')}, label={sample_row.get('label', 'N/A')}, http_status={sample_row.get('http_status', 'N/A')}")

        return output_file

    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check HTTP status for URLs in a CSV file.")
    parser.add_argument("--input-file", required=True, help="Path to the input CSV file (must contain a 'url' column).")
    parser.add_argument("--output-dir", required=True, help="Directory to save the output CSV file.")
    args = parser.parse_args()

    output_file_path = asyncio.run(process_urls_async(args.input_file, args.output_dir))

    if output_file_path:
        log.info(f"Processing complete. Output saved to: {output_file_path}")
    else:
        log.error(f"Processing failed for input file: {args.input_file}")
        exit(1)