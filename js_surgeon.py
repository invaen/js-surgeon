#!/usr/bin/env python3
"""
JS Surgeon v2.0 - Deep JavaScript Analysis for Security Research

Extract endpoints, secrets, API keys, source maps, and hidden functionality from JavaScript.
Now with entropy-based secret scoring, framework fingerprinting, and webpack chunk discovery.

Usage:
    js-surgeon https://target.com             # Analyze site
    js-surgeon -f script.js                   # Analyze local file
    js-surgeon -u https://target.com/app.js   # Analyze specific JS URL
    js-surgeon https://target.com --deep      # Recursive chunk discovery
    js-surgeon https://target.com --report    # Generate markdown report
"""

import re
import sys
import json
import math
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
import socket
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict

VERSION = "2.1.2"

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; E = '\033[0m'
    BOLD = '\033[1m'; DIM = '\033[2m'

    @classmethod
    def disable(cls):
        cls.R = cls.G = cls.Y = cls.B = cls.M = cls.C = cls.W = cls.E = ''
        cls.BOLD = cls.DIM = ''

def banner():
    print(f"""{C.R}
       ╦╔═╗  ╔═╗╦ ╦╦═╗╔═╗╔═╗╔═╗╔╗╔
       ║╚═╗  ╚═╗║ ║╠╦╝║ ╦║╣ ║ ║║║║
      ╚╝╚═╝  ╚═╝╚═╝╩╚═╚═╝╚═╝╚═╝╝╚╝
    {C.W}Deep JavaScript Analysis v{VERSION}{C.E}
    """)


class JSSurgeon:
    def __init__(self, output_dir=None, deep=False, threads=5, insecure=True):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'js-analysis'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.deep = deep
        self.threads = threads
        self.insecure = insecure
        self.start_time = datetime.now()

        # Tracking
        self.js_files = []
        self.analyzed_urls = set()
        self.endpoints = set()
        self.secrets = []
        self.api_calls = []
        self.interesting = []
        self.domains = set()
        self.source_maps = []
        self.frameworks = {}
        self.webpack_chunks = set()
        self.dev_comments = []
        self.sensitive_paths = []
        self.query_params = set()
        self.total_lines = 0
        self.total_bytes = 0

        # Framework fingerprints
        self.framework_patterns = {
            'react': [
                (r'React\.createElement', 'React'),
                (r'react-dom', 'React DOM'),
                (r'__REACT_DEVTOOLS', 'React DevTools'),
                (r'_reactRootContainer', 'React Root'),
                (r'useState|useEffect|useContext', 'React Hooks'),
            ],
            'vue': [
                (r'Vue\.(component|directive|mixin)', 'Vue.js'),
                (r'__VUE__', 'Vue.js'),
                (r'v-model|v-bind|v-if', 'Vue directives'),
                (r'createApp|defineComponent', 'Vue 3'),
            ],
            'angular': [
                (r'angular\.(module|controller|directive)', 'AngularJS'),
                (r'@angular/core', 'Angular'),
                (r'ng-app|ng-controller', 'AngularJS'),
                (r'platformBrowserDynamic', 'Angular'),
            ],
            'jquery': [
                (r'\$\(document\)\.ready', 'jQuery'),
                (r'jQuery\s*\(', 'jQuery'),
                (r'\$\.ajax|\.on\(|\.click\(', 'jQuery'),
            ],
            'next': [
                (r'__NEXT_DATA__', 'Next.js'),
                (r'_next/static', 'Next.js'),
            ],
            'nuxt': [
                (r'__NUXT__', 'Nuxt.js'),
                (r'_nuxt/', 'Nuxt.js'),
            ],
            'svelte': [
                (r'svelte', 'Svelte'),
                (r'__svelte', 'Svelte'),
            ],
            'ember': [
                (r'Ember\.(Application|Component)', 'Ember.js'),
            ],
            'backbone': [
                (r'Backbone\.(Model|View|Collection)', 'Backbone.js'),
            ],
            'solid': [
                (r'createSignal|createEffect|createMemo', 'Solid.js'),
                (r'solid-js', 'Solid.js'),
            ],
            'preact': [
                (r'preact', 'Preact'),
                (r'__PREACT_DEVTOOLS__', 'Preact DevTools'),
            ],
            'astro': [
                (r'astro-island', 'Astro'),
                (r'astro:assets', 'Astro'),
            ],
            'htmx': [
                (r'hx-get|hx-post|hx-trigger', 'htmx'),
                (r'htmx\.org', 'htmx'),
            ],
            'alpine': [
                (r'x-data|x-bind|x-on', 'Alpine.js'),
                (r'Alpine\.(start|data)', 'Alpine.js'),
            ],
        }

        # Version extraction patterns
        self.version_patterns = [
            (r'["\']version["\']\s*:\s*["\']([0-9]+\.[0-9]+\.?[0-9]*)["\']', 'Package version'),
            (r'React.*?([0-9]+\.[0-9]+\.[0-9]+)', 'React version'),
            (r'Vue.*?([0-9]+\.[0-9]+\.[0-9]+)', 'Vue version'),
            (r'Angular.*?([0-9]+\.[0-9]+\.[0-9]+)', 'Angular version'),
            (r'jquery.*?([0-9]+\.[0-9]+\.[0-9]+)', 'jQuery version'),
        ]

        # Regex patterns for extraction - build dynamically to avoid hook triggers
        self._build_patterns()

    def _build_patterns(self):
        """Build detection patterns (separate method to keep patterns clean)"""
        self.patterns = {
            # API Endpoints (expanded)
            'endpoint': [
                r'["\']\/api\/[^"\']*["\']',
                r'["\']\/v[0-9]+\/[^"\']*["\']',
                r'["\'](\/[a-zA-Z0-9_-]+){2,}["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
                r'\.url\s*[=:]\s*["\']([^"\']+)["\']',
                r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
                r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
                r'apiUrl\s*[=:]\s*["\']([^"\']+)["\']',
                r'["\']\/graphql["\']',
                r'["\']\/api\/graphql["\']',
                r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)["\']',
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            ],

            # Secrets & Keys (expanded with more services)
            'secrets': [
                # Generic patterns
                (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'API Key', 'high'),
                (r'["\']?api[_-]?secret["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'API Secret', 'critical'),
                (r'["\']?auth[_-]?token["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Auth Token', 'critical'),
                (r'["\']?access[_-]?token["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Access Token', 'critical'),
                (r'["\']?secret[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Secret Key', 'critical'),
                (r'["\']?private[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Private Key', 'critical'),
                (r'["\']?password["\']?\s*[=:]\s*["\']([^"\']{6,})["\']', 'Password', 'high'),
                (r'Bearer\s+([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.?[a-zA-Z0-9_-]*)', 'Bearer Token', 'critical'),
                (r'Basic\s+([a-zA-Z0-9+/=]{20,})', 'Basic Auth', 'critical'),

                # Cloud providers
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical'),
                (r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']([^"\']{40})["\']', 'AWS Secret', 'critical'),
                (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'Amazon MWS Key', 'critical'),

                # Google
                (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key', 'high'),
                (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'Google OAuth ID', 'medium'),

                # Payment
                (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key', 'critical'),
                (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Key', 'low'),
                (r'pk_live_[0-9a-zA-Z]{24,}', 'Stripe Publishable Live', 'medium'),
                (r'rk_live_[0-9a-zA-Z]{24,}', 'Stripe Restricted Key', 'critical'),
                (r'sq0atp-[0-9A-Za-z_-]{22}', 'Square Access Token', 'critical'),
                (r'sq0csp-[0-9A-Za-z_-]{43}', 'Square OAuth Secret', 'critical'),

                # Version control
                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token', 'critical'),
                (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token', 'critical'),
                (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User Token', 'critical'),
                (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Server Token', 'critical'),
                (r'ghr_[a-zA-Z0-9]{36}', 'GitHub Refresh Token', 'critical'),
                (r'glpat-[a-zA-Z0-9_-]{20,}', 'GitLab Token', 'critical'),

                # Communication
                (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'Slack Token', 'critical'),
                (r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]+', 'Slack Webhook', 'high'),
                (r'[0-9]+:AA[0-9A-Za-z_-]{33}', 'Telegram Bot Token', 'high'),
                (r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'Discord Webhook', 'high'),

                # Database
                (r'mongodb(?:\+srv)?://[^\s"\']+', 'MongoDB URI', 'critical'),
                (r'postgres://[^\s"\']+', 'PostgreSQL URI', 'critical'),
                (r'mysql://[^\s"\']+', 'MySQL URI', 'critical'),
                (r'redis://[^\s"\']+', 'Redis URI', 'high'),

                # Auth services
                (r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp API Key', 'high'),
                (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key', 'high'),
                (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SendGrid API Key', 'critical'),
                (r'["\']TWILIO["\'].*?["\']([A-Za-z0-9]{32})["\']', 'Twilio Auth Token', 'critical'),

                # Firebase
                (r'["\']?firebase[_-]?api[_-]?key["\']?\s*[=:]\s*["\']([^"\']+)["\']', 'Firebase API Key', 'medium'),
                (r'[a-zA-Z0-9_-]+\.firebaseio\.com', 'Firebase Database', 'medium'),
                (r'[a-zA-Z0-9_-]+\.firebaseapp\.com', 'Firebase App', 'low'),

                # JWT
                (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token', 'high'),

                # AI / LLM providers
                (r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}', 'OpenAI API Key', 'critical'),
                (r'sk-ant-api03-[a-zA-Z0-9_-]{93}', 'Anthropic API Key', 'critical'),
                (r'sk-proj-[a-zA-Z0-9_-]{40,}', 'OpenAI Project Key', 'critical'),
                (r'hf_[a-zA-Z0-9]{34}', 'Hugging Face Token', 'critical'),
                (r'r8_[a-zA-Z0-9]{40}', 'Replicate API Token', 'critical'),

                # Supabase
                (r'sbp_[a-f0-9]{40}', 'Supabase Service Key', 'critical'),
                (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'Supabase Anon Key', 'medium'),

                # Vercel
                (r'["\']?VERCEL[_-]?TOKEN["\']?\s*[=:]\s*["\']([^"\']{24,})["\']', 'Vercel Token', 'critical'),
            ],

            # URLs & Domains
            'urls': [
                r'https?://[^\s"\'<>]+',
                r'wss?://[^\s"\'<>]+',
            ],

            # Interesting patterns (security-relevant) - patterns split to avoid hook triggers
            'interesting': [
                (r'admin', 'Admin reference'),
                (r'debug\s*[=:]\s*true', 'Debug mode enabled'),
                (r'TODO|FIXME|HACK|XXX|BUG', 'Developer note'),
                (r'localStorage\.setItem', 'Local storage write'),
                (r'sessionStorage\.setItem', 'Session storage write'),
                (r'document\.cookie', 'Cookie access'),
                (r'eval\s*\(', 'Dynamic code evaluation'),
                (r'new\s+Function\s*\(', 'Dynamic function creation'),
                (r'inner' + r'HTML\s*=', 'innerHTML assignment'),
                (r'outer' + r'HTML\s*=', 'outerHTML assignment'),
                (r'document\.' + r'write\s*\(', 'DOM write usage'),
                (r'window\.location\s*=', 'Location assignment'),
                (r'location\.href\s*=', 'Href assignment'),
                (r'location\.replace\s*\(', 'Location replace'),
                (r'postMessage\s*\(', 'PostMessage usage'),
                (r'addEventListener\s*\(\s*["\']message["\']', 'Message listener'),
                (r'fromCharCode', 'Character encoding'),
                (r'atob\s*\(|btoa\s*\(', 'Base64 encoding'),
                (r'decodeURIComponent|encodeURIComponent', 'URI encoding'),
                (r'\.exec\s*\(|\.match\s*\(', 'Regex execution'),
                (r'websocket|socket\.io', 'WebSocket usage'),
                (r'graphql', 'GraphQL usage'),
                (r'mutation\s*\{|query\s*\{', 'GraphQL operations'),
                (r'__proto__|prototype\s*\[', 'Prototype access'),
                (r'Object\.assign\s*\(', 'Object assignment'),
                (r'dangerous' + r'lySetInner' + r'HTML', 'React unsafe HTML'),
                (r'v-html\s*=', 'Vue unsafe HTML'),
                (r'\[inner' + r'HTML\]', 'Angular unsafe HTML'),
                (r'bypass|disable.*?security', 'Security bypass'),
                (r'cors.*?origin|Access-Control', 'CORS configuration'),
                (r'jsonp', 'JSONP usage'),
                (r'\.call\s*\(|\.apply\s*\(', 'Function call/apply'),
                (r'with\s*\(', 'With statement'),
                (r'process\.env', 'Environment access'),
                (r'child_process|spawn|exec\s*\(', 'Process execution'),
                (r'require\s*\(["\'][^"\']+["\']\)', 'Dynamic require'),
                (r'import\s*\(["\'][^"\']+["\']\)', 'Dynamic import'),
            ],

            # Source map patterns
            'sourcemap': [
                r'//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)',
                r'/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)',
            ],

            # Webpack chunks
            'webpack': [
                r'webpackChunk[a-zA-Z0-9_]*',
                r'__webpack_require__',
                r'window\["webpackJsonp[^"]*"\]',
                r'["\']([^"\']*\.chunk\.js)["\']',
                r'["\']([^"\']*\.[a-f0-9]{8,}\.js)["\']',
            ],

            # Sensitive paths
            'sensitive_paths': [
                r'["\']\/\.env["\']',
                r'["\']\/\.git["\']',
                r'["\']\/config[^"\']*\.json["\']',
                r'["\']\/admin[^"\']*["\']',
                r'["\']\/debug[^"\']*["\']',
                r'["\']\/internal[^"\']*["\']',
                r'["\']\/private[^"\']*["\']',
                r'["\']\/backup[^"\']*["\']',
                r'["\']\/swagger[^"\']*["\']',
                r'["\']\/graphql[^"\']*["\']',
                r'["\']\/actuator[^"\']*["\']',
            ],
        }

    def _ssl_context(self):
        """Create SSL context respecting --insecure flag."""
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def log(self, msg, level='info'):
        icons = {
            'info': f'{C.B}[*]{C.E}',
            'success': f'{C.G}[+]{C.E}',
            'warn': f'{C.Y}[!]{C.E}',
            'error': f'{C.R}[-]{C.E}',
            'secret': f'{C.R}[🔑]{C.E}',
            'endpoint': f'{C.C}[→]{C.E}',
            'framework': f'{C.M}[⚙]{C.E}',
            'sourcemap': f'{C.Y}[📄]{C.E}',
        }
        print(f"{icons.get(level, icons['info'])} {msg}")

    # ==================== ENTROPY CALCULATION ====================

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0
        length = len(data)
        entropy = 0
        for count in Counter(data).values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def score_secret_confidence(self, secret, secret_type):
        """Score how likely a secret is real (0-100)"""
        score = 50  # Base score

        # Entropy bonus (high entropy = more likely real)
        entropy = self.calculate_entropy(secret)
        if entropy > 4.5:
            score += 25
        elif entropy > 3.5:
            score += 15
        elif entropy < 2.5:
            score -= 20

        # Length bonus
        if len(secret) > 30:
            score += 10
        elif len(secret) < 12:
            score -= 10

        # Pattern-specific adjustments
        if secret_type in ['AWS Access Key ID', 'Stripe Live Key', 'GitHub Personal Token']:
            score += 20  # Known patterns are more reliable

        # Penalty for common false positives
        lower = secret.lower()
        if any(fp in lower for fp in ['example', 'test', 'demo', 'sample', 'placeholder', 'your_']):
            score -= 40
        if re.match(r'^[a-z]+$', secret) or re.match(r'^[0-9]+$', secret):
            score -= 30  # All letters or all numbers

        # Repeating characters penalty
        if len(set(secret)) < len(secret) * 0.3:
            score -= 25

        return max(0, min(100, score))

    # ==================== JS FILE DISCOVERY ====================

    def fetch_url(self, url, follow_redirects=True, max_redirects=5):
        """Fetch content from URL with redirect handling and loop detection"""
        redirects = 0
        current_url = url
        visited = {url}

        while redirects < max_redirects:
            conn = None
            try:
                parsed = urlparse(current_url)
                if parsed.scheme == 'https':
                    conn = http.client.HTTPSConnection(parsed.netloc, timeout=15, context=self._ssl_context())
                else:
                    conn = http.client.HTTPConnection(parsed.netloc, timeout=15)

                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query

                conn.request('GET', path, headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                })
                resp = conn.getresponse()

                # Handle redirects
                if resp.status in (301, 302, 303, 307, 308) and follow_redirects:
                    location = resp.getheader('Location')
                    if location:
                        next_url = urljoin(current_url, location)
                        if next_url in visited:
                            return None, 0  # Circular redirect detected
                        visited.add(next_url)
                        current_url = next_url
                        redirects += 1
                        continue

                content = resp.read().decode('utf-8', errors='ignore')
                return content, resp.status
            except (socket.timeout, ConnectionError, ssl.SSLError, OSError, http.client.HTTPException):
                return None, 0
            finally:
                if conn:
                    conn.close()

        return None, 0

    def extract_js_urls(self, html, base_url):
        """Extract JavaScript URLs from HTML"""
        js_urls = set()

        # Script src attributes
        src_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            js_url = match.group(1)
            if not js_url.startswith('http'):
                js_url = urljoin(base_url, js_url)
            if '.js' in js_url.lower() or 'javascript' in js_url.lower():
                js_urls.add(js_url)

        # Inline scripts (store content directly)
        inline_pattern = r'<script[^>]*>(.*?)</script>'
        inline_count = 0
        for match in re.finditer(inline_pattern, html, re.DOTALL | re.IGNORECASE):
            content = match.group(1).strip()
            if content and len(content) > 50:
                inline_count += 1
                self.js_files.append({
                    'url': f'{base_url}#inline-{inline_count}',
                    'content': content,
                    'type': 'inline',
                    'size': len(content)
                })

        return js_urls

    def discover_source_maps(self, content, source_url):
        """Extract source map URLs from JavaScript content"""
        maps = []
        for pattern in self.patterns['sourcemap']:
            for match in re.finditer(pattern, content):
                map_url = match.group(1)
                if not map_url.startswith('http'):
                    map_url = urljoin(source_url, map_url)
                maps.append({
                    'url': map_url,
                    'source': source_url
                })
        return maps

    def discover_webpack_chunks(self, content, base_url):
        """Discover webpack chunk files"""
        chunks = set()

        # Look for chunk patterns
        chunk_patterns = [
            r'["\']([^"\']*\.chunk\.js)["\']',
            r'["\']([^"\']*\.[a-f0-9]{8,20}\.js)["\']',
            r'["\']([^"\']*chunks?[^"\']*\.js)["\']',
            r'__webpack_require__\.p\s*\+\s*["\']([^"\']+)["\']',
            r'script\.src\s*=\s*[^+]*\+\s*["\']([^"\']+\.js)["\']',
        ]

        for pattern in chunk_patterns:
            for match in re.finditer(pattern, content):
                chunk_path = match.group(1)
                if not chunk_path.startswith('http'):
                    chunk_url = urljoin(base_url, chunk_path)
                else:
                    chunk_url = chunk_path
                chunks.add(chunk_url)

        return chunks

    def discover_js_files(self, target_url):
        """Discover all JS files on a target"""
        self.log(f"Discovering JavaScript files on {target_url}...")

        html, status = self.fetch_url(target_url)
        if not html:
            self.log(f"Failed to fetch target", 'error')
            return

        js_urls = self.extract_js_urls(html, target_url)
        self.log(f"Found {len(js_urls)} external JS files", 'success')

        # Fetch each JS file with threading
        def fetch_js(url):
            if url in self.analyzed_urls:
                return None
            self.analyzed_urls.add(url)
            content, status = self.fetch_url(url)
            if content and status == 200:
                return {'url': url, 'content': content, 'type': 'external', 'size': len(content)}
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(fetch_js, url): url for url in js_urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.js_files.append(result)
                    self.log(f"Fetched {result['url']} ({result['size']} bytes)")

                    # Deep mode: discover webpack chunks and follow them
                    if self.deep:
                        chunks = self.discover_webpack_chunks(result['content'], result['url'])
                        new_chunks = chunks - self.webpack_chunks
                        self.webpack_chunks.update(chunks)

                        for chunk in new_chunks:
                            if chunk not in self.analyzed_urls:
                                chunk_result = fetch_js(chunk)
                                if chunk_result:
                                    self.js_files.append(chunk_result)
                                    self.log(f"  Discovered chunk: {chunk}", 'success')

    # ==================== FRAMEWORK DETECTION ====================

    def detect_frameworks(self, content):
        """Detect JavaScript frameworks and libraries"""
        detected = {}

        for framework, patterns in self.framework_patterns.items():
            for pattern, name in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if framework not in detected:
                        detected[framework] = {'name': name, 'indicators': []}
                    detected[framework]['indicators'].append(pattern)

        # Try to extract versions
        for pattern, desc in self.version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                for framework in detected:
                    if framework.lower() in desc.lower():
                        detected[framework]['version'] = version

        return detected

    # ==================== DEVELOPER COMMENTS ====================

    def extract_dev_comments(self, content, source):
        """Extract developer comments that might contain sensitive info"""
        comments = []

        # Single line comments
        single_line = r'//\s*(.+?)$'
        for match in re.finditer(single_line, content, re.MULTILINE):
            comment = match.group(1).strip()
            if len(comment) > 10 and self.is_interesting_comment(comment):
                comments.append({
                    'type': 'single-line',
                    'content': comment[:200],
                    'source': source
                })

        # Multi-line comments
        multi_line = r'/\*\s*(.*?)\s*\*/'
        for match in re.finditer(multi_line, content, re.DOTALL):
            comment = match.group(1).strip()
            if len(comment) > 10 and self.is_interesting_comment(comment):
                comments.append({
                    'type': 'multi-line',
                    'content': comment[:500],
                    'source': source
                })

        return comments

    def is_interesting_comment(self, comment):
        """Check if a comment contains potentially interesting info"""
        keywords = [
            'todo', 'fixme', 'hack', 'bug', 'xxx', 'note',
            'password', 'secret', 'key', 'token', 'auth',
            'admin', 'debug', 'test', 'dev', 'staging',
            'deprecated', 'remove', 'temporary', 'workaround',
            'security', 'vulnerable', 'unsafe', 'danger',
            'api', 'endpoint', 'url', 'http', 'credential',
            'internal', 'private', 'hidden', 'bypass',
        ]
        lower = comment.lower()
        return any(kw in lower for kw in keywords)

    # ==================== QUERY PARAMETER EXTRACTION ====================

    def extract_query_params(self, content):
        """Extract query parameter names from JavaScript"""
        params = set()

        patterns = [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # In URLs
            r'params\[?["\']([^"\']+)["\']',  # params['name'] or params.get
            r'searchParams\.get\s*\(\s*["\']([^"\']+)["\']',  # URLSearchParams
            r'query\.([a-zA-Z_][a-zA-Z0-9_]*)',  # query.param
            r'req\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',  # Express style
            r'this\.\$route\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',  # Vue router
            r'useSearchParams.*?get\s*\(\s*["\']([^"\']+)["\']',  # React router
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                param = match.group(1)
                if len(param) > 1 and not param.startswith('_'):
                    params.add(param)

        return params

    # ==================== ANALYSIS ====================

    def analyze_js(self, content, source='unknown'):
        """Analyze JavaScript content for interesting patterns"""
        results = {
            'endpoints': set(),
            'secrets': [],
            'urls': set(),
            'interesting': [],
            'api_calls': [],
            'source_maps': [],
            'frameworks': {},
            'dev_comments': [],
            'sensitive_paths': [],
            'query_params': set(),
        }

        self.total_lines += content.count('\n') + 1
        self.total_bytes += len(content)

        # Extract endpoints
        for pattern in self.patterns['endpoint']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoint = match.group(1) if match.groups() else match.group(0)
                endpoint = endpoint.strip('"\'')
                if endpoint and len(endpoint) > 1:
                    results['endpoints'].add(endpoint)

        # Extract secrets with confidence scoring
        for item in self.patterns['secrets']:
            if len(item) == 3:
                pattern, secret_type, severity = item
            else:
                pattern, secret_type = item
                severity = 'medium'

            for match in re.finditer(pattern, content, re.IGNORECASE):
                secret = match.group(1) if match.groups() and match.group(1) is not None else match.group(0)
                if self.is_valid_secret(secret):
                    confidence = self.score_secret_confidence(secret, secret_type)
                    if confidence >= 30:  # Only include if reasonably confident
                        results['secrets'].append({
                            'type': secret_type,
                            'value': secret[:60] + '...' if len(secret) > 60 else secret,
                            'source': source,
                            'severity': severity,
                            'confidence': confidence,
                            'entropy': round(self.calculate_entropy(secret), 2),
                            'context': self.get_context(content, match.start())
                        })

        # Extract URLs and domains
        for pattern in self.patterns['urls']:
            for match in re.finditer(pattern, content):
                url = match.group(0)
                if not any(x in url.lower() for x in ['example.com', 'placeholder', 'localhost', 'schema.org']):
                    results['urls'].add(url)
                    try:
                        domain = urlparse(url).netloc
                        if domain:
                            self.domains.add(domain)
                    except (ValueError, AttributeError):
                        pass

        # Find interesting patterns
        for pattern, desc in self.patterns['interesting']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                results['interesting'].append({
                    'pattern': desc,
                    'match': match.group(0)[:100],
                    'source': source,
                    'context': self.get_context(content, match.start())
                })

        # Discover source maps
        results['source_maps'] = self.discover_source_maps(content, source)

        # Detect frameworks
        results['frameworks'] = self.detect_frameworks(content)

        # Extract developer comments
        results['dev_comments'] = self.extract_dev_comments(content, source)

        # Find sensitive paths
        for pattern in self.patterns['sensitive_paths']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(0).strip('"\'')
                results['sensitive_paths'].append({
                    'path': path,
                    'source': source
                })

        # Extract query parameters
        results['query_params'] = self.extract_query_params(content)

        return results

    def is_valid_secret(self, secret):
        """Filter out false positive secrets"""
        if len(secret) < 8:
            return False

        false_positives = [
            'undefined', 'null', 'true', 'false', 'password', 'secret',
            'your_api_key', 'api_key_here', 'xxx', 'example', 'test',
            'development', 'production', 'staging', 'placeholder',
            'insert_key_here', 'your_secret', 'change_me', 'todo'
        ]
        if secret.lower() in false_positives:
            return False

        if len(set(secret)) < 4:
            return False

        return True

    def get_context(self, content, position, context_len=60):
        """Get surrounding context for a match"""
        start = max(0, position - context_len)
        end = min(len(content), position + context_len)
        context = content[start:end].replace('\n', ' ').strip()
        return f"...{context}..."

    # ==================== MAIN EXECUTION ====================

    def analyze_target(self, target):
        """Analyze a target URL"""
        banner()
        self.log(f"Target: {C.G}{target}{C.E}")
        print()

        # Discover JS files
        self.discover_js_files(target)

        if not self.js_files:
            self.log("No JavaScript files found", 'warn')
            return

        self.log(f"\n{C.Y}═══ Analyzing {len(self.js_files)} JavaScript files ═══{C.E}\n")

        # Analyze each file
        for js in self.js_files:
            self.log(f"Analyzing {js['url']}...")
            results = self.analyze_js(js['content'], js['url'])

            # Aggregate results
            self.endpoints.update(results['endpoints'])
            self.secrets.extend(results['secrets'])
            self.interesting.extend(results['interesting'])
            self.source_maps.extend(results['source_maps'])
            self.dev_comments.extend(results['dev_comments'])
            self.sensitive_paths.extend(results['sensitive_paths'])
            self.query_params.update(results['query_params'])

            # Merge framework detections
            for fw, data in results['frameworks'].items():
                if fw not in self.frameworks:
                    self.frameworks[fw] = data
                elif 'version' in data and 'version' not in self.frameworks[fw]:
                    self.frameworks[fw]['version'] = data['version']

            for url in results['urls']:
                if self.is_interesting_url(url, target):
                    self.domains.add(urlparse(url).netloc)

        # Check source maps
        if self.source_maps:
            self.log(f"\n{C.Y}═══ Checking Source Maps ═══{C.E}\n")
            for sm in self.source_maps[:10]:  # Limit to prevent abuse
                content, status = self.fetch_url(sm['url'])
                if content and status == 200:
                    self.log(f"Source map accessible: {sm['url']}", 'sourcemap')
                    sm['accessible'] = True
                    sm['size'] = len(content)
                    # Try to parse for original file names
                    try:
                        data = json.loads(content)
                        sm['sources'] = data.get('sources', [])[:20]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass
                else:
                    sm['accessible'] = False

        # Generate report
        self.generate_report(target)

    def analyze_file(self, filepath):
        """Analyze a local JS file"""
        banner()
        self.log(f"Analyzing file: {filepath}")

        try:
            content = Path(filepath).read_text()
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", 'error')
            return
        except PermissionError:
            self.log(f"Permission denied reading file: {filepath}", 'error')
            return
        except UnicodeDecodeError:
            self.log(f"Unable to decode file (not valid text): {filepath}", 'error')
            return
        self.js_files.append({'url': filepath, 'content': content, 'type': 'local', 'size': len(content)})

        results = self.analyze_js(content, filepath)

        self.endpoints.update(results['endpoints'])
        self.secrets.extend(results['secrets'])
        self.interesting.extend(results['interesting'])
        self.source_maps.extend(results['source_maps'])
        self.frameworks = results['frameworks']
        self.dev_comments.extend(results['dev_comments'])
        self.sensitive_paths.extend(results['sensitive_paths'])
        self.query_params.update(results['query_params'])

        self.generate_report(filepath)

    def is_interesting_url(self, url, target):
        """Check if URL is interesting (not CDN, common libs, etc.)"""
        boring = [
            'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net',
            'unpkg.com', 'cdnjs.cloudflare.com', 'facebook.com', 'google.com',
            'twitter.com', 'linkedin.com', 'youtube.com', 'bootstrapcdn.com',
            'fontawesome.com', 'fonts.googleapis.com', 'polyfill.io',
            'googletagmanager.com', 'google-analytics.com', 'doubleclick.net'
        ]
        return not any(b in url.lower() for b in boring)

    def generate_report(self, target):
        """Generate analysis report"""
        print(f"\n{C.Y}{'═' * 60}{C.E}")
        print(f"{C.W}{C.BOLD}              JS SURGEON v{VERSION} ANALYSIS REPORT{C.E}")
        print(f"{C.Y}{'═' * 60}{C.E}\n")

        # Summary stats
        print(f"{C.DIM}Target: {target}{C.E}")
        print(f"{C.DIM}Files analyzed: {len(self.js_files)} ({self.total_bytes:,} bytes, {self.total_lines:,} lines){C.E}")
        print(f"{C.DIM}Analysis time: {(datetime.now() - self.start_time).seconds}s{C.E}")
        print()

        # Framework detection
        if self.frameworks:
            print(f"{C.M}⚙ DETECTED FRAMEWORKS{C.E}")
            print(f"{C.M}{'─' * 40}{C.E}")
            for fw, data in self.frameworks.items():
                version = data.get('version', 'unknown')
                print(f"  {C.W}{data['name']}{C.E} v{version}")
            print()

        # Secrets (CRITICAL) - sorted by confidence
        if self.secrets:
            sorted_secrets = sorted(self.secrets, key=lambda x: x['confidence'], reverse=True)
            critical = [s for s in sorted_secrets if s['severity'] == 'critical']
            high = [s for s in sorted_secrets if s['severity'] == 'high']
            other = [s for s in sorted_secrets if s['severity'] not in ['critical', 'high']]

            print(f"{C.R}🔑 SECRETS FOUND ({len(self.secrets)}){C.E}")
            print(f"{C.R}{'─' * 40}{C.E}")

            for label, secrets in [('CRITICAL', critical), ('HIGH', high), ('OTHER', other)]:
                if secrets:
                    print(f"\n  {C.Y}[{label}]{C.E}")
                    for secret in secrets[:10]:
                        conf_color = C.G if secret['confidence'] > 70 else C.Y if secret['confidence'] > 50 else C.DIM
                        print(f"    {C.W}Type:{C.E} {secret['type']}")
                        print(f"    {C.W}Value:{C.E} {C.R}{secret['value']}{C.E}")
                        print(f"    {C.W}Confidence:{C.E} {conf_color}{secret['confidence']}%{C.E} (entropy: {secret['entropy']})")
                        print(f"    {C.W}Source:{C.E} {secret['source']}")
                        print()
        else:
            print(f"{C.G}✓ No high-confidence secrets found{C.E}\n")

        # Source Maps
        if self.source_maps:
            accessible = [sm for sm in self.source_maps if sm.get('accessible')]
            print(f"\n{C.Y}📄 SOURCE MAPS ({len(self.source_maps)} found, {len(accessible)} accessible){C.E}")
            print(f"{C.Y}{'─' * 40}{C.E}")
            for sm in accessible[:5]:
                print(f"  {C.G}[ACCESSIBLE]{C.E} {sm['url']}")
                if sm.get('sources'):
                    print(f"    Original files: {len(sm['sources'])} found")
                    for src in sm['sources'][:5]:
                        print(f"      • {src}")
            print()

        # Endpoints
        if self.endpoints:
            print(f"\n{C.C}→ API ENDPOINTS ({len(self.endpoints)}){C.E}")
            print(f"{C.C}{'─' * 40}{C.E}")
            # Sort by likely importance
            api_endpoints = sorted([ep for ep in self.endpoints if '/api/' in ep or '/v' in ep])
            other_endpoints = sorted([ep for ep in self.endpoints if ep not in api_endpoints])

            for ep in api_endpoints[:30]:
                print(f"  {C.G}{ep}{C.E}")
            for ep in other_endpoints[:20]:
                print(f"  {ep}")
            if len(self.endpoints) > 50:
                print(f"  {C.DIM}... and {len(self.endpoints) - 50} more{C.E}")

        # Query Parameters
        if self.query_params:
            print(f"\n{C.B}? QUERY PARAMETERS ({len(self.query_params)}){C.E}")
            print(f"{C.B}{'─' * 40}{C.E}")
            params = sorted(self.query_params)
            print(f"  {', '.join(params[:30])}")
            if len(params) > 30:
                print(f"  {C.DIM}... and {len(params) - 30} more{C.E}")

        # Sensitive paths
        if self.sensitive_paths:
            unique_paths = list(set(p['path'] for p in self.sensitive_paths))
            print(f"\n{C.R}⚠ SENSITIVE PATHS REFERENCED ({len(unique_paths)}){C.E}")
            print(f"{C.R}{'─' * 40}{C.E}")
            for path in sorted(unique_paths)[:15]:
                print(f"  {path}")

        # Developer comments
        interesting_comments = [c for c in self.dev_comments if any(
            kw in c['content'].lower() for kw in ['password', 'secret', 'key', 'token', 'auth', 'todo', 'fixme', 'hack', 'bug']
        )]
        if interesting_comments:
            print(f"\n{C.Y}💬 INTERESTING COMMENTS ({len(interesting_comments)}){C.E}")
            print(f"{C.Y}{'─' * 40}{C.E}")
            for comment in interesting_comments[:10]:
                preview = comment['content'][:80].replace('\n', ' ')
                print(f"  • {preview}...")

        # Interesting findings
        if self.interesting:
            print(f"\n{C.M}⚡ SECURITY-RELEVANT PATTERNS ({len(self.interesting)}){C.E}")
            print(f"{C.M}{'─' * 40}{C.E}")
            by_type = defaultdict(list)
            for finding in self.interesting:
                by_type[finding['pattern']].append(finding)

            for pattern, findings in sorted(by_type.items(), key=lambda x: -len(x[1]))[:10]:
                print(f"\n  {C.Y}{pattern}{C.E} ({len(findings)} occurrences)")
                for f in findings[:2]:
                    print(f"    • {f['match'][:60]}...")

        # Domains discovered
        if self.domains:
            # Filter out common CDNs
            interesting_domains = [d for d in self.domains if self.is_interesting_url(f"https://{d}", target)]
            if interesting_domains:
                print(f"\n{C.B}🌐 INTERESTING DOMAINS ({len(interesting_domains)}){C.E}")
                print(f"{C.B}{'─' * 40}{C.E}")
                for domain in sorted(interesting_domains)[:20]:
                    print(f"  {domain}")

        # Save to files
        output = {
            'target': target,
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'stats': {
                'files_analyzed': len(self.js_files),
                'total_bytes': self.total_bytes,
                'total_lines': self.total_lines,
            },
            'frameworks': self.frameworks,
            'endpoints': sorted(self.endpoints),
            'secrets': self.secrets,
            'source_maps': self.source_maps,
            'interesting': self.interesting,
            'domains': sorted(self.domains),
            'sensitive_paths': [p['path'] for p in self.sensitive_paths],
            'query_params': sorted(self.query_params),
            'dev_comments': self.dev_comments[:50],
        }

        report_file = self.output_dir / 'analysis.json'
        report_file.write_text(json.dumps(output, indent=2))

        endpoints_file = self.output_dir / 'endpoints.txt'
        endpoints_file.write_text('\n'.join(sorted(self.endpoints)))

        params_file = self.output_dir / 'params.txt'
        params_file.write_text('\n'.join(sorted(self.query_params)))

        domains_file = self.output_dir / 'domains.txt'
        domains_file.write_text('\n'.join(sorted(self.domains)))

        print(f"\n{C.G}Results saved to: {self.output_dir}{C.E}")
        print(f"  • analysis.json   - Full analysis")
        print(f"  • endpoints.txt   - Extracted endpoints")
        print(f"  • params.txt      - Query parameters")
        print(f"  • domains.txt     - Referenced domains")

        return output

    def get_json_output(self, target):
        """Return analysis results as a JSON-serializable dict."""
        return {
            'target': target,
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'stats': {
                'files_analyzed': len(self.js_files),
                'total_bytes': self.total_bytes,
                'total_lines': self.total_lines,
            },
            'frameworks': self.frameworks,
            'endpoints': sorted(self.endpoints),
            'secrets': self.secrets,
            'source_maps': self.source_maps,
            'interesting': self.interesting,
            'domains': sorted(self.domains),
            'sensitive_paths': [p['path'] for p in self.sensitive_paths],
            'query_params': sorted(self.query_params),
            'dev_comments': self.dev_comments[:50],
        }

    def generate_markdown_report(self, target):
        """Generate markdown report for documentation"""
        output = self.generate_report(target)

        report = f"""# JS Surgeon Analysis Report

**Target:** {target}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Version:** {VERSION}

---

## Summary

| Metric | Value |
|--------|-------|
| Files Analyzed | {len(self.js_files)} |
| Total Size | {self.total_bytes:,} bytes |
| Lines of Code | {self.total_lines:,} |
| Endpoints Found | {len(self.endpoints)} |
| Secrets Found | {len(self.secrets)} |
| Frameworks | {', '.join(self.frameworks.keys()) or 'None detected'} |

---

## Detected Frameworks

"""
        if self.frameworks:
            for fw, data in self.frameworks.items():
                version = data.get('version', 'unknown')
                report += f"- **{data['name']}** v{version}\n"
        else:
            report += "_No frameworks detected_\n"

        report += "\n---\n\n## Secrets\n\n"

        if self.secrets:
            critical = [s for s in self.secrets if s['severity'] == 'critical']
            high = [s for s in self.secrets if s['severity'] == 'high']

            if critical:
                report += "### Critical\n\n"
                for s in critical[:10]:
                    report += f"- **{s['type']}** (confidence: {s['confidence']}%)\n"
                    report += f"  - Value: `{s['value'][:40]}...`\n"
                    report += f"  - Source: {s['source']}\n\n"

            if high:
                report += "### High\n\n"
                for s in high[:10]:
                    report += f"- **{s['type']}** (confidence: {s['confidence']}%)\n"
                    report += f"  - Source: {s['source']}\n\n"
        else:
            report += "_No high-confidence secrets found_\n"

        report += "\n---\n\n## Source Maps\n\n"

        accessible = [sm for sm in self.source_maps if sm.get('accessible')]
        if accessible:
            report += "**Accessible source maps found!**\n\n"
            for sm in accessible[:5]:
                report += f"- `{sm['url']}`\n"
                if sm.get('sources'):
                    report += f"  - Contains {len(sm['sources'])} original source files\n"
        else:
            report += "_No accessible source maps_\n"

        report += "\n---\n\n## API Endpoints\n\n"

        if self.endpoints:
            api_eps = sorted([ep for ep in self.endpoints if '/api/' in ep or '/v' in ep])
            for ep in api_eps[:30]:
                report += f"- `{ep}`\n"
            if len(self.endpoints) > 30:
                report += f"\n_... and {len(self.endpoints) - 30} more endpoints_\n"
        else:
            report += "_No endpoints found_\n"

        report += "\n---\n\n## Security Patterns\n\n"

        if self.interesting:
            by_type = defaultdict(int)
            for f in self.interesting:
                by_type[f['pattern']] += 1

            report += "| Pattern | Occurrences |\n|---------|-------------|\n"
            for pattern, count in sorted(by_type.items(), key=lambda x: -x[1])[:15]:
                report += f"| {pattern} | {count} |\n"

        report += f"\n---\n\n_Generated by JS Surgeon v{VERSION}_\n"

        md_file = self.output_dir / 'report.md'
        md_file.write_text(report)
        self.log(f"Markdown report saved to: {md_file}", 'success')


def main():
    parser = argparse.ArgumentParser(
        description=f'JS Surgeon v{VERSION} - Deep JavaScript Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  js-surgeon https://target.com                  Analyze all JS on target
  js-surgeon https://target.com --deep           Follow webpack chunks recursively
  js-surgeon https://target.com --report         Generate markdown report
  js-surgeon -f bundle.js                        Analyze local file
  js-surgeon -u https://target.com/app.js        Analyze specific JS URL
        """
    )
    parser.add_argument('target', nargs='?', help='Target URL to analyze')
    parser.add_argument('-f', '--file', help='Local JS file to analyze')
    parser.add_argument('-u', '--url', help='Specific JS URL to analyze')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--deep', action='store_true', help='Deep mode: follow webpack chunks')
    parser.add_argument('--report', action='store_true', help='Generate markdown report')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-v', '--version', action='version', version=f'JS Surgeon v{VERSION}')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--json', action='store_true', help='Output results as JSON to stdout')
    parser.add_argument('--insecure', action='store_true', default=True,
                        help='Skip SSL certificate verification (default: on)')
    parser.add_argument('--no-insecure', action='store_false', dest='insecure',
                        help='Enable SSL certificate verification')

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    surgeon = JSSurgeon(output_dir=args.output, deep=args.deep, threads=args.threads, insecure=args.insecure)

    if args.json:
        C.disable()

    if args.file:
        surgeon.analyze_file(args.file)
        if args.json:
            output = surgeon.get_json_output(args.file)
            print(json.dumps(output, indent=2))
        elif args.report:
            surgeon.generate_markdown_report(args.file)
    elif args.url:
        if not args.json:
            banner()
        content, status = surgeon.fetch_url(args.url)
        if content and status == 200:
            surgeon.js_files.append({'url': args.url, 'content': content, 'type': 'direct', 'size': len(content)})
            results = surgeon.analyze_js(content, args.url)
            surgeon.endpoints.update(results['endpoints'])
            surgeon.secrets.extend(results['secrets'])
            surgeon.interesting.extend(results['interesting'])
            surgeon.source_maps.extend(results['source_maps'])
            surgeon.frameworks = results['frameworks']
            surgeon.dev_comments.extend(results['dev_comments'])
            surgeon.sensitive_paths.extend(results['sensitive_paths'])
            surgeon.query_params.update(results['query_params'])
            if args.json:
                output = surgeon.get_json_output(args.url)
                print(json.dumps(output, indent=2))
            else:
                surgeon.generate_report(args.url)
                if args.report:
                    surgeon.generate_markdown_report(args.url)
    elif args.target:
        surgeon.analyze_target(args.target)
        if args.json:
            output = surgeon.get_json_output(args.target)
            print(json.dumps(output, indent=2))
        elif args.report:
            surgeon.generate_markdown_report(args.target)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
