import argparse
import subprocess
import requests
import re
from urllib.parse import urljoin

def run_command(command):
    """ Execute shell command and return output. """
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    return result.stdout.strip()

def save_results(filename, data):
    """ Save data to a text file with formatting. """
    with open(filename, 'a') as file:
        file.write(data + "\n\n")

def check_ssl_certificates(url):
    """ Check SSL certificates using SSLScan. """
    return run_command(f"sslscan {url}")

def perform_nmap_scan(target):
    """ Perform an Nmap scan with -p- -sVC options. """
    return run_command(f"nmap -p- -sVC {target}")

def run_nikto_scan(url):
    """ Run a Nikto web server scanner. """
    return run_command(f"nikto -h {url}")

def run_dirsearch(url):
    """ Run Dirsearch for directory enumeration. """
    return run_command(f"dirsearch -u {url} -e php,html,js -x 403,404,500")

def run_nuclei(url):
    """ Run Nuclei scanner. """
    return run_command(f"nuclei -u {url} -severity critical,high")

def check_cors(url):
    """ Check CORS by sending a request and examining headers. """
    response = requests.get(url)
    cors_headers = response.headers.get('Access-Control-Allow-Origin')
    return cors_headers

def check_options_method(url):
    """ Use OPTIONS method to check allowed HTTP methods. """
    response = requests.options(url)
    allowed_methods = response.headers.get('Allow')
    return allowed_methods

def check_security_headers(url):
    """ Check for missing security headers. """
    response = requests.get(url)
    headers_to_check = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
    missing_headers = [h for h in headers_to_check if h not in response.headers]
    return missing_headers

def check_server_version(url):
    """ Check server version from the headers. """
    response = requests.get(url)
    server_version = response.headers.get('Server')
    return server_version

def javascript_analysis(url):
    """ Analyze JavaScript files for secrets and hardcoded endpoints. """
    response = requests.get(url)
    script_urls = re.findall(r'<script src="([^"]+)">', response.text)
    findings = []
    for script_url in script_urls:
        full_url = urljoin(url, script_url)
        js_content = requests.get(full_url).text
        secrets = re.findall(r'[\w-]{40,}', js_content)  # Regex to find potential tokens or keys
        if secrets:
            findings.append(f"Potential secrets in {script_url}: {', '.join(secrets)}")
    return "JavaScript Analysis Results:\n" + "\n".join(findings)

def directory_listing_test(url):
    """ Test for directory listing vulnerabilities. """
    response = requests.get(url)
    if "Index of" in response.text:
        return f"Directory listing is enabled at {url}"
    return f"No directory listing at {url}"

def site_crawler(url):
    """ Simple crawler to discover endpoints on the site. """
    response = requests.get(url)
    links = re.findall(r'href="([^"]+)"', response.text)
    endpoints = set(urljoin(url, link) for link in links if link.startswith('/'))
    return "Discovered endpoints:\n" + "\n".join(endpoints)

# Argument parsing
parser = argparse.ArgumentParser(description='Perform security scans on a domain or IP address.')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-d', '--domain', type=str, help='Domain to scan')
group.add_argument('-i', '--ip', type=str, help='IP address to scan')
args = parser.parse_args()

# Determine target based on input
target_url = f"http://{args.domain}" if args.domain else f"http://{args.ip}"
target_ip = args.ip if args.ip else args.domain

# Run scans
ssl_results = check_ssl_certificates(target_url)
nmap_results = perform_nmap_scan(target_ip)
nikto_results = run_nikto_scan(target_url)
nuclei_results = run_nuclei(target_url)
cors_results = check_cors(target_url)
options_results = check_options_method(target_url)
security_headers = check_security_headers(target_url)
server_version = check_server_version(target_url)
js_analysis_results = javascript_analysis(target_url)
directory_listing = directory_listing_test(target_url)
crawled_endpoints = site_crawler(target_url)

# Save results
result_filename = "scan_results.txt"
save_results(result_filename, ssl_results)
save_results(result_filename, nmap_results)
save_results(result_filename, nikto_results)
save_results(result_filename, nuclei_results)
save_results(result_filename, cors_results)
save_results(result_filename, options_results)
save_results(result_filename, security_headers)
save_results(result_filename, server_version)
save_results(result_filename, js_analysis_results)
save_results(result_filename, directory_listing)
save_results(result_filename, crawled_endpoints)

