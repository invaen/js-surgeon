<p align="center">
  <h1 align="center">JS Surgeon</h1>
  <p align="center">
    <b>Extract secrets, endpoints, and attack surface from JavaScript.</b>
    <br />
    <i>Static analysis for bug bounty hunters — finds what grep misses.</i>
  </p>
</p>

<p align="center">
  <a href="#what-it-finds">What It Finds</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#detection-patterns">Detection Patterns</a> &bull;
  <a href="#output">Output</a>
</p>

---

JS Surgeon performs deep static analysis on JavaScript files to extract hardcoded secrets, API endpoints, internal domains, and security-relevant patterns. It crawls a target site, pulls every JS file (external and inline), and runs 50+ regex patterns against the content to surface findings that manual review would miss.

```
SECRETS FOUND (3)
  Type: AWS Access Key
  Value: AKIAIOSFODNN7EXAMPLE...
  Source: https://target.com/static/app.bundle.js

API ENDPOINTS (47)
  /api/v2/users/profile
  /api/v2/admin/settings
  /internal/debug/trace
  ...

INTERESTING PATTERNS (12)
  Dynamic code execution (potential injection) (2 occurrences)
  Debug mode enabled (1 occurrence)
  innerHTML assignment (XSS risk) (4 occurrences)
```

## What It Finds

| Category | Examples |
|----------|----------|
| **API Keys & Secrets** | AWS keys, Stripe keys, GitHub tokens, Google API keys, Slack tokens, Bearer tokens, generic API keys/secrets |
| **API Endpoints** | REST paths, fetch/axios calls, jQuery AJAX, GraphQL operations |
| **Security Anti-patterns** | Dynamic code execution, innerHTML sinks, cookie access, postMessage, open redirect vectors |
| **Debug Artifacts** | Debug flags, TODO/FIXME/HACK comments, development endpoints |
| **Internal Infrastructure** | Internal domains, WebSocket URLs, third-party service integrations |

## Install

```bash
git clone https://github.com/invaen/js-surgeon.git
cd js-surgeon
python js_surgeon.py https://target.com

# Or install with pip
pip install .
js-surgeon https://target.com
```

**Requirements:** Python 3.8+. No external packages.

## Usage

```bash
# Analyze a live target — crawls HTML, extracts all JS files, analyzes each
js-surgeon https://target.com

# Analyze a specific JS file by URL
js-surgeon -u https://target.com/static/app.bundle.js

# Analyze a local JavaScript file
js-surgeon -f downloaded_script.js

# Custom output directory
js-surgeon https://target.com -o ./results
```

## Detection Patterns

### Secrets (16 patterns)

JS Surgeon detects secrets using context-aware regex that reduces false positives by filtering out placeholder values, short strings, and common variable names:

- AWS Access Key ID / Secret Access Key
- Google API Key (`AIza...`)
- Stripe Live/Test Keys (`sk_live_` / `sk_test_`)
- GitHub Personal Access Token (`ghp_`)
- GitLab Personal Access Token (`glpat-`)
- Slack Tokens (`xoxb-`, `xoxp-`)
- Generic API keys, secrets, auth tokens, passwords
- Bearer tokens (JWT and opaque)

### Endpoints (8 patterns)

Extracts API paths from multiple coding styles:

```javascript
fetch('/api/v2/users')           // fetch() calls
axios.get('/api/admin/settings') // axios calls
$.post('/legacy/endpoint')       // jQuery AJAX
url: '/internal/service'         // config objects
endpoint = '/graphql'            // variable assignments
```

### Security Patterns (17 patterns)

Flags code constructs that indicate potential vulnerabilities:

- Dynamic code execution — injection vectors
- DOM manipulation via innerHTML — XSS sinks
- Cookie access via document.cookie — session theft surface
- Location assignment — open redirect candidates
- Cross-origin messaging via postMessage
- Client-side storage of sensitive data
- Base64 encoding/decoding — possible obfuscation
- GraphQL queries and mutations — API schema exposure

## Output

Results save to `./js-analysis/` (or custom path with `-o`):

```
js-analysis/
├── analysis.json    # Full structured results
└── endpoints.txt    # One endpoint per line (for feeding into other tools)
```

### Pipeline Integration

```bash
# Feed endpoints into ffuf for fuzzing
js-surgeon https://target.com
cat js-analysis/endpoints.txt | while read ep; do
  ffuf -u "https://target.com${ep}" -w /dev/null -mc all
done

# Parse secrets from report
cat js-analysis/analysis.json | jq '.secrets[] | "\(.type): \(.value)"'

# Chain with ghost-recon — analyze JS on discovered subdomains
cat subdomains.txt | while read sub; do
  js-surgeon "https://$sub" -o "js-results/$sub"
done
```

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Only analyze JavaScript from applications you have explicit permission to test. The author assumes no liability for misuse.

## License

MIT
