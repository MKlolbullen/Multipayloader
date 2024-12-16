# Multipayloader
A beta test for a multi target attack with a multi payload type.
Here’s a comprehensive README.md file for your GitHub repository:

I'll be working to expand and enhance the capabilities of this, it's just something I threw together from my phone, so yeah... Contributions are welcomed.

---

MultiPayloadAttacker / Automated Vulnerability Scanner

An automated vulnerability scanner designed to discover and test potential security vulnerabilities in web applications. This tool leverages popular subdomain and URL discovery tools like assetfinder, subfinder, urlfinder, and gospider, combined with a suite of payloads targeting various vulnerabilities.

Features

Payload Categories:

XSS (Cross-Site Scripting): Tests for reflected, stored, and DOM-based XSS vulnerabilities.

LFI (Local File Inclusion): Detects improper inclusion of local files like /etc/passwd.

SQLi (SQL Injection): Identifies SQL injection vulnerabilities in web parameters.

DOM XSS: Tests for client-side JavaScript execution vulnerabilities.

SSTI (Server-Side Template Injection): Exploits template rendering engines for code execution.

SSRF (Server-Side Request Forgery): Detects vulnerabilities that allow servers to make unauthorized requests.

RCE (Remote Code Execution): Identifies vulnerabilities allowing arbitrary command execution on the server.


Automated URL Collection:

Uses assetfinder, subfinder, httprobe, urlfinder, and gospider to discover subdomains and endpoints.

Consolidates and deduplicates URLs for efficient testing.


Payload Encoding:

Ensures payloads are safely encoded for testing in URLs and parameters.


Concurrent Testing:

Utilizes ThreadPoolExecutor for fast, parallel vulnerability testing.


Result Logging:

Saves results to both JSON and CSV formats for easy analysis and sharing.


Color-Coded Output:

Green: Confirmed or potential vulnerabilities.

Yellow: Testing in progress.

Red: Errors or failed tests.

Blue: Informational messages.




---

Installation

Prerequisites

1. Python 3.7+


2. Install required tools:

assetfinder

`go install github.com/tomnomnom/assetfinder@latest`

subfinder

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

httprobe

`go install github.com/tomnomnom/httprobe@latest`

urlfinder

`pip install urlfinder`

gospider

`go install github.com/jaeles-project/gospider@latest`


curl
I'm assuming that you already have python, golang and curl installed.


---

Usage

Running the Script

1. Clone the repository:
`
git clone https://github.com/MKlolbullen/MultiPayloader.git
cd MultiPayloader
`


2. Run the script:
`
python3 MPA.py
`

3. Enter the target domain when prompted:

Enter domain: example.com


4. The script will:

Collect URLs using discovery tools.

Test each URL for vulnerabilities using the provided payloads.

Save results to results.json and results.csv.


---

Example Output


Terminal Output:


```
Enter domain: example.com

Collecting URLs...
URL collection complete. Saved to real_output.txt.

Processing URLs for vulnerabilities...

Analyzing https://example.com/page...
[XSS] Testing: https://example.com/page?param=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
[XSS] Success: https://example.com/page?param=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
[LFI] Testing: https://example.com/page?param=..%2F..%2Fetc%2Fpasswd
[LFI] Success: https://example.com/page?param=..%2F..%2Fetc%2Fpasswd

Results saved to results.json.
Results saved to results.csv.

Results File (JSON):



[
    {
        "url": "https://example.com/page?param=..%2F..%2Fetc%2Fpasswd",
        "type": "LFI",
        "payload": "../../../../etc/passwd",
        "status": "Potential Vulnerability"
    }
]

```

---

Configuration

Adjust Concurrency

Modify the MAX_WORKERS variable to control the number of concurrent requests:

MAX_WORKERS = 20  # Adjust based on system resources


---

Extending the Scanner

1. Add New Payloads:

Define a new list for payloads (e.g., new_vuln_payloads).

Add a call to test_url_with_payloads in the analyze_url function.



2. Integrate Additional Tools:

Add subprocess calls to integrate other tools for URL or vulnerability discovery.



3. Enhance Logging:

Modify the save_results function to include additional fields or formats.



---

Disclaimer

This tool is intended for ethical hacking and security research purposes only. Do not use it on domains or applications without proper authorization. The authors are not responsible for any misuse of this tool.


---

Contributing

Contributions are welcome! To contribute:

1. Fork this repository.


2. Create a new branch (feature/new-feature).


3. Commit your changes.


4. Push to the branch.


5. Open a Pull Request.


---

License

This project is licensed under the MIT License.


---

Author

MKlolbullen

Feel free to open issues or reach out with feedback or suggestions!



