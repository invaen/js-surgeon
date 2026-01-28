#!/usr/bin/env python3
"""
JS Surgeon - Deep JavaScript Analysis

Extract endpoints, secrets, API keys, and hidden functionality from JavaScript.

Usage:
    python surgeon.py https://target.com             # Analyze site
    python surgeon.py -f script.js                   # Analyze local file
    python surgeon.py -u https://target.com/app.js  # Analyze specific JS URL
"""

import re
import sys
import json
import argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; E = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""{C.R}
       ╦╔═╗  ╔═╗╦ ╦╦═╗╔═╗╔═╗╔═╗╔╗╔
       ║╚═╗  ╚═╗║ ║╠╦╝║ ╦║╣ ║ ║║║║
      ╚╝╚═╝  ╚═╝╚═╝╩╚═╚═╝╚═╝╚═╝╝╚╝
    {C.W}Extract secrets from JavaScript{C.E}
    """)

class JSSurgeon:
    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'js-analysis'
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.js_files = []
        self.endpoints = set()
        self.secrets = []
        self.api_calls = []
        self.interesting = []
        self.domains = set()

        # Regex patterns for extraction
        self.patterns = {
            # API Endpoints
            'endpoint': [
                r'["\']\/api\/[^"\']*["\']',
                r'["\']\/v[0-9]+\/[^"\']*["\']',
                r'["\'](\/[a-zA-Z0-9_-]+){2,}["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
                r'\.url\s*[=:]\s*["\']([^"\']+)["\']',
                r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
            ],

            # Secrets & Keys
            'secrets': [
                (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'API Key'),
                (r'["\']?api[_-]?secret["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'API Secret'),
                (r'["\']?auth[_-]?token["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Auth Token'),
                (r'["\']?access[_-]?token["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Access Token'),
                (r'["\']?secret[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Secret Key'),
                (r'["\']?private[_-]?key["\']?\s*[=:]\s*["\']([^"\']{10,})["\']', 'Private Key'),
                (r'["\']?password["\']?\s*[=:]\s*["\']([^"\']{6,})["\']', 'Password'),
                (r'Bearer\s+([a-zA-Z0-9_-]+\.?[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*)', 'Bearer Token'),
                (r'["\']?aws[_-]?access[_-]?key[_-]?id["\']?\s*[=:]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
                (r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']([^"\']{40})["\']', 'AWS Secret'),
                (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
                (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key'),
                (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Key'),
                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
                (r'glpat-[a-zA-Z0-9_-]{20}', 'GitLab Token'),
                (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'Slack Token'),
            ],

            # URLs & Domains
            'urls': [
                r'https?://[^\s"\'<>]+',
                r'wss?://[^\s"\'<>]+',
            ],

            # Interesting patterns
            'interesting': [
                (r'admin', 'Admin reference'),
                (r'debug\s*[=:]\s*true', 'Debug mode enabled'),
                (r'TODO|FIXME|HACK|XXX', 'Developer note'),
                (r'localStorage\.setItem', 'Local storage usage'),
                (r'document\.cookie', 'Cookie access'),
                (r'eval\s*\(', 'Eval usage (potential injection)'),
                (r'innerHTML\s*=', 'innerHTML assignment (XSS risk)'),
                (r'\.innerText\s*=.*\+', 'Dynamic text (potential XSS)'),
                (r'window\.location\s*=', 'Redirect (potential open redirect)'),
                (r'postMessage\s*\(', 'PostMessage (potential XSS)'),
                (r'new\s+Function\s*\(', 'Dynamic function creation'),
                (r'fromCharCode', 'Character encoding (obfuscation)'),
                (r'atob|btoa', 'Base64 encoding'),
                (r'\.exec\s*\(|\.match\s*\(', 'Regex execution'),
                (r'websocket|socket\.io', 'WebSocket usage'),
                (r'graphql', 'GraphQL usage'),
                (r'mutation\s*{|query\s*{', 'GraphQL operations'),
            ],

            # HTTP Methods with endpoints
            'api_calls': [
                r'method\s*[=:]\s*["\']?(GET|POST|PUT|DELETE|PATCH)["\']?',
            ]
        }

    def log(self, msg, level='info'):
        icons = {'info': f'{C.B}[*]{C.E}', 'success': f'{C.G}[+]{C.E}',
                 'warn': f'{C.Y}[!]{C.E}', 'error': f'{C.R}[-]{C.E}',
                 'secret': f'{C.R}[🔑]{C.E}', 'endpoint': f'{C.C}[→]{C.E}'}
        print(f"{icons.get(level, icons['info'])} {msg}")

    # ==================== JS FILE DISCOVERY ====================

    def fetch_url(self, url):
        """Fetch content from URL"""
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(parsed.netloc, timeout=10, context=context)
            else:
                conn = http.client.HTTPConnection(parsed.netloc, timeout=10)

            conn.request('GET', parsed.path or '/', headers={
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            })
            resp = conn.getresponse()
            content = resp.read().decode('utf-8', errors='ignore')
            conn.close()
            return content
        except Exception as e:
            self.log(f"Failed to fetch {url}: {e}", 'warn')
            return None

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
            if content and len(content) > 50:  # Skip tiny inline scripts
                inline_count += 1
                self.js_files.append({
                    'url': f'{base_url}#inline-{inline_count}',
                    'content': content,
                    'type': 'inline'
                })

        return js_urls

    def discover_js_files(self, target_url):
        """Discover all JS files on a target"""
        self.log(f"Discovering JavaScript files on {target_url}...")

        html = self.fetch_url(target_url)
        if not html:
            return

        js_urls = self.extract_js_urls(html, target_url)
        self.log(f"Found {len(js_urls)} external JS files", 'success')

        # Fetch each JS file
        for url in js_urls:
            self.log(f"Fetching {url}...")
            content = self.fetch_url(url)
            if content:
                self.js_files.append({
                    'url': url,
                    'content': content,
                    'type': 'external'
                })

    # ==================== ANALYSIS ====================

    def analyze_js(self, content, source='unknown'):
        """Analyze JavaScript content for interesting patterns"""
        results = {
            'endpoints': set(),
            'secrets': [],
            'urls': set(),
            'interesting': [],
            'api_calls': []
        }

        # Extract endpoints
        for pattern in self.patterns['endpoint']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoint = match.group(1) if match.groups() else match.group(0)
                endpoint = endpoint.strip('"\'')
                if endpoint and len(endpoint) > 1:
                    results['endpoints'].add(endpoint)

        # Extract secrets
        for pattern, secret_type in self.patterns['secrets']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                secret = match.group(1) if match.groups() else match.group(0)
                # Filter false positives
                if self.is_valid_secret(secret):
                    results['secrets'].append({
                        'type': secret_type,
                        'value': secret[:50] + '...' if len(secret) > 50 else secret,
                        'source': source,
                        'context': self.get_context(content, match.start())
                    })

        # Extract URLs
        for pattern in self.patterns['urls']:
            for match in re.finditer(pattern, content):
                url = match.group(0)
                if not any(x in url.lower() for x in ['example.com', 'placeholder', 'localhost']):
                    results['urls'].add(url)
                    # Extract domain
                    try:
                        domain = urlparse(url).netloc
                        if domain:
                            self.domains.add(domain)
                    except:
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

        return results

    def is_valid_secret(self, secret):
        """Filter out false positive secrets"""
        # Too short
        if len(secret) < 8:
            return False

        # Common false positives
        false_positives = [
            'undefined', 'null', 'true', 'false', 'password', 'secret',
            'your_api_key', 'api_key_here', 'xxx', 'example', 'test',
            'development', 'production', 'staging'
        ]
        if secret.lower() in false_positives:
            return False

        # All same character
        if len(set(secret)) < 3:
            return False

        return True

    def get_context(self, content, position, context_len=50):
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
            for url in results['urls']:
                if self.is_interesting_url(url, target):
                    self.domains.add(urlparse(url).netloc)

        # Generate report
        self.generate_report(target)

    def analyze_file(self, filepath):
        """Analyze a local JS file"""
        banner()
        self.log(f"Analyzing file: {filepath}")

        content = Path(filepath).read_text()
        results = self.analyze_js(content, filepath)

        self.endpoints.update(results['endpoints'])
        self.secrets.extend(results['secrets'])
        self.interesting.extend(results['interesting'])

        self.generate_report(filepath)

    def is_interesting_url(self, url, target):
        """Check if URL is interesting (not CDN, common libs, etc.)"""
        boring = ['googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net',
                  'unpkg.com', 'cdnjs.cloudflare.com', 'facebook.com', 'google.com',
                  'twitter.com', 'linkedin.com', 'youtube.com', 'bootstrapcdn.com']
        return not any(b in url.lower() for b in boring)

    def generate_report(self, target):
        """Generate analysis report"""
        print(f"\n{C.Y}{'═' * 50}{C.E}")
        print(f"{C.W}{C.BOLD}           JS SURGEON ANALYSIS REPORT{C.E}")
        print(f"{C.Y}{'═' * 50}{C.E}\n")

        # Secrets (CRITICAL)
        if self.secrets:
            print(f"{C.R}🔑 SECRETS FOUND ({len(self.secrets)}){C.E}")
            print(f"{C.R}{'─' * 40}{C.E}")
            for secret in self.secrets[:20]:
                print(f"  {C.Y}Type:{C.E} {secret['type']}")
                print(f"  {C.Y}Value:{C.E} {C.R}{secret['value']}{C.E}")
                print(f"  {C.Y}Source:{C.E} {secret['source']}")
                print()
        else:
            print(f"{C.G}✓ No obvious secrets found{C.E}\n")

        # Endpoints
        if self.endpoints:
            print(f"\n{C.C}→ API ENDPOINTS ({len(self.endpoints)}){C.E}")
            print(f"{C.C}{'─' * 40}{C.E}")
            for ep in sorted(self.endpoints)[:50]:
                print(f"  {ep}")

        # Interesting findings
        if self.interesting:
            print(f"\n{C.M}⚡ INTERESTING PATTERNS ({len(self.interesting)}){C.E}")
            print(f"{C.M}{'─' * 40}{C.E}")
            # Group by pattern type
            by_type = {}
            for finding in self.interesting:
                t = finding['pattern']
                if t not in by_type:
                    by_type[t] = []
                by_type[t].append(finding)

            for pattern, findings in by_type.items():
                print(f"\n  {C.Y}{pattern}{C.E} ({len(findings)} occurrences)")
                for f in findings[:3]:
                    print(f"    • {f['match'][:60]}...")

        # Domains discovered
        if self.domains:
            print(f"\n{C.B}🌐 DOMAINS REFERENCED ({len(self.domains)}){C.E}")
            print(f"{C.B}{'─' * 40}{C.E}")
            for domain in sorted(self.domains)[:20]:
                print(f"  {domain}")

        # Save to files
        output = {
            'target': target,
            'endpoints': list(self.endpoints),
            'secrets': self.secrets,
            'interesting': self.interesting,
            'domains': list(self.domains)
        }

        report_file = self.output_dir / 'analysis.json'
        report_file.write_text(json.dumps(output, indent=2))

        endpoints_file = self.output_dir / 'endpoints.txt'
        endpoints_file.write_text('\n'.join(sorted(self.endpoints)))

        print(f"\n{C.G}Results saved to: {self.output_dir}{C.E}")
        print(f"  • analysis.json - Full analysis")
        print(f"  • endpoints.txt - Extracted endpoints")


def main():
    parser = argparse.ArgumentParser(description='JS Surgeon - Deep JavaScript Analysis')
    parser.add_argument('target', nargs='?', help='Target URL to analyze')
    parser.add_argument('-f', '--file', help='Local JS file to analyze')
    parser.add_argument('-u', '--url', help='Specific JS URL to analyze')
    parser.add_argument('-o', '--output', help='Output directory')

    args = parser.parse_args()

    surgeon = JSSurgeon(output_dir=args.output)

    if args.file:
        surgeon.analyze_file(args.file)
    elif args.url:
        banner()
        content = surgeon.fetch_url(args.url)
        if content:
            surgeon.js_files.append({'url': args.url, 'content': content, 'type': 'direct'})
            results = surgeon.analyze_js(content, args.url)
            surgeon.endpoints.update(results['endpoints'])
            surgeon.secrets.extend(results['secrets'])
            surgeon.interesting.extend(results['interesting'])
            surgeon.generate_report(args.url)
    elif args.target:
        surgeon.analyze_target(args.target)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
