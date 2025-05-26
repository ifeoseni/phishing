import os
import re
import pandas as pd
import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse
import tldextract

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ensure_url_scheme(url: str) -> str:
    """Ensure URL has http:// or https:// scheme"""
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return f'http://{url}'
    return url

def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain"""
    def get_domain(u):
        parsed = urlparse(ensure_url_scheme(u))
        domain = parsed.netloc.split(':')[0]  # Remove port
        return tldextract.extract(domain).registered_domain
    
    return get_domain(url1) == get_domain(url2)

def check_http_status(url: str) -> dict:
    """Check HTTP response status and activity"""
    result = {
        'url': url,
        'http_status': 0,
        'is_active': 0,
        'has_redirect': 0,
        
    }
    
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
            
            # Check for redirect headers
            if no_redirect_response.is_redirect and 'Location' in no_redirect_response.headers:
                location = no_redirect_response.headers['Location']
                if not is_same_domain(url, location):
                    result.update({
                        'http_status': no_redirect_response.status_code,
                        'is_active': 1,
                        'has_redirect': 1,
                        'final_url': location
                    })
                    return result
        
        except requests.exceptions.SSLError:
            # If SSL error, try without verification
            no_redirect_response = requests.head(
                url_with_scheme,
                headers=headers,
                timeout=10,
                allow_redirects=False,
                verify=False
            )
            
            if no_redirect_response.is_redirect and 'Location' in no_redirect_response.headers:
                location = no_redirect_response.headers['Location']
                if not is_same_domain(url, location):
                    result.update({
                        'http_status': no_redirect_response.status_code,
                        'is_active': 1,
                        'has_redirect': 1,
                        'final_url': location
                    })
                    return result
        
        # Now make the full request following redirects
        response = requests.get(
            url_with_scheme,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=False
        )
        
        # Check if we were redirected outside original domain
        has_redirect = 0
        if len(response.history) > 0:
            for resp in response.history:
                if resp.is_redirect and 'Location' in resp.headers:
                    if not is_same_domain(url, resp.headers['Location']):
                        has_redirect = 1
                        break
        
        result.update({
            'http_status': response.status_code,
            'is_active': 1,
            'has_redirect': has_redirect,
            # 'final_url': response.url
        })
        
    except Exception as e:
        if isinstance(e, (requests.exceptions.ConnectionError, 
                         requests.exceptions.Timeout,
                         requests.exceptions.TooManyRedirects)):
            # No server response or unreachable
            pass
        elif isinstance(e, requests.exceptions.RequestException):
            # Other request exceptions (treated as server responded)
            result['is_active'] = 1
    
    return result

def process_urls_for_status(input_csv: str, output_dir: str) -> bool:
    """Process URLs from input CSV and save HTTP status info"""
    try:
        df = pd.read_csv(input_csv)
        
        if 'url' not in df.columns:
            raise ValueError("Input CSV must contain a 'url' column with URLs")
        
        print(f"Processing {len(df)} URLs for HTTP status...")
        
        results = []
        for url in df['url']:
            print(f"Checking: {url}")
            status_info = check_http_status(url)
            results.append(status_info)
        
        status_df = pd.DataFrame(results)
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamped output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"http_status_{timestamp}.csv")
        
        status_df.to_csv(output_file, index=False)
        print(f"HTTP status results saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error processing URLs: {e}")
        return False

if __name__ == "__main__":
    input_file = "dataset-cleaning/remove_duplicate_from_combined_dataset.csv" #test_data.csv"  # Input CSV with 'url' column
    output_dir = "http_status"  # Directory to save results
    
    success = process_urls_for_status(input_file, output_dir)
    if not success:
        print("Failed to process URLs")