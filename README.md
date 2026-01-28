<p align="center">
  <h1 align="center">JS Surgeon</h1>
  <p align="center">
    <b>Extract secrets, endpoints, and attack surface from JavaScript.</b>
    <br />
    <i>Deep static analysis for bug bounty hunters — finds what grep misses.</i>
  </p>
</p>

<p align="center">
  <a href="#whats-new-in-v20">What's New</a> &bull;
  <a href="#what-it-finds">What It Finds</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#detection-patterns">Detection Patterns</a>
</p>

---

JS Surgeon performs deep static analysis on JavaScript files to extract hardcoded secrets, API endpoints, source maps, framework fingerprints, and security-relevant patterns. It crawls a target site, pulls every JS file (external and inline), and runs 70+ detection patterns with entropy-based confidence scoring to surface high-value findings.

```
⚙ DETECTED FRAMEWORKS
  React v18.2.0
  Next.js

🔑 SECRETS FOUND (3)
  [CRITICAL]
    Type: AWS Access Key ID
    Value: AKIAIOSFODNN7EXAMPLE
    Confidence: 85% (entropy: 4.72)
    Source: https://target.com/static/app.bundle.js

📄 SOURCE MAPS (2 found, 1 accessible)
  [ACCESSIBLE] https://target.com/static/app.bundle.js.map
    Original files: 47 found

→ API ENDPOINTS (52)
  /api/v2/users/profile
  /api/v2/admin/settings
  /internal/debug/trace
```

## What's New in v2.0

| Feature | Description |
|---------|-------------|
| **Entropy-Based Scoring** | Shannon entropy analysis reduces false positives — secrets scored 0-100% confidence |
| **Framework Detection** | Identifies React, Vue, Angular, Next.js, Nuxt, jQuery, Svelte, Ember, Backbone with version extraction |
| **Source Map Discovery** | Finds and validates `.map` files, extracts original source file names |
| **Webpack Chunk Following** | `--deep` mode recursively discovers and analyzes chunked bundles |
| **Query Parameter Extraction** | Pulls parameter names from URL patterns, URLSearchParams, router usage |
| **Developer Comment Mining** | Extracts TODO/FIXME/HACK comments and security-related notes |
| **Sensitive Path Detection** | Flags references to `/admin`, `/debug`, `/.env`, `/swagger`, etc. |
| **Expanded Secret Patterns** | 40+ patterns covering AWS, GCP, Stripe, GitHub, GitLab, Slack, Firebase, MongoDB, and more |
| **Markdown Reports** | `--report` generates professional markdown documentation |

## What It Finds

| Category | Examples |
|----------|----------|
| **Secrets & Keys** | AWS (AKIA*), Stripe (sk_live_), GitHub (ghp_), Google (AIza*), Slack (xox*), Firebase, MongoDB URIs, JWTs, Bearer tokens |
| **API Endpoints** | REST paths, fetch/axios calls, jQuery AJAX, GraphQL, WebSocket URLs |
| **Source Maps** | .map file references with accessibility check and original source extraction |
| **Frameworks** | React, Vue, Angular, Next.js, Nuxt, jQuery, Svelte with version detection |
| **Security Patterns** | Dynamic code execution, DOM sinks, cookie access, postMessage, prototype pollution vectors |
| **Query Parameters** | URL params, URLSearchParams, Express req.query, Vue/React router params |
| **Dev Artifacts** | Debug flags, TODO/FIXME comments, internal endpoints, sensitive path references |

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

# Deep mode — follow webpack chunks recursively
js-surgeon https://target.com --deep

# Generate markdown report
js-surgeon https://target.com --report

# Analyze a specific JS file by URL
js-surgeon -u https://target.com/static/app.bundle.js

# Analyze a local JavaScript file
js-surgeon -f downloaded_script.js

# Custom output directory with threading
js-surgeon https://target.com -o ./results -t 10

# Show version
js-surgeon -v
```

## Detection Patterns

### Secrets (40+ patterns)

JS Surgeon detects secrets using context-aware regex with entropy scoring. High-entropy strings with known patterns score higher confidence:

**Cloud & Infrastructure**
- AWS Access Key ID (`AKIA...`) / Secret Access Key
- Google API Key (`AIza...`) / OAuth Client ID
- Firebase API Key / Database URLs

**Payment**
- Stripe Live/Test/Restricted Keys (`sk_live_`, `sk_test_`, `rk_live_`)
- Square Access Tokens

**Version Control**
- GitHub Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitLab Personal Access Token (`glpat-`)

**Communication**
- Slack Tokens (`xoxb-`, `xoxp-`) / Webhooks
- Discord Webhooks
- Telegram Bot Tokens

**Database**
- MongoDB / PostgreSQL / MySQL / Redis connection URIs

**Auth**
- JWT tokens
- Bearer/Basic auth
- SendGrid, Twilio, Mailchimp, Mailgun API keys

### Framework Detection

Fingerprints JavaScript frameworks by detecting characteristic patterns:

```
⚙ DETECTED FRAMEWORKS
  React v18.2.0          (useState, useEffect, React.createElement)
  Next.js                (__NEXT_DATA__, _next/static)
  jQuery v3.6.0          ($.ajax, $(document).ready)
```

Supported: React, Vue (2/3), Angular, Next.js, Nuxt, Svelte, Ember, Backbone, jQuery

### Source Map Analysis

Discovers and validates source map files:

```
📄 SOURCE MAPS (2 found, 1 accessible)
  [ACCESSIBLE] https://target.com/static/app.bundle.js.map
    Original files: 47 found
      • src/components/Auth.tsx
      • src/utils/apiClient.ts
      • src/hooks/useSession.ts
```

### Security Patterns (30+ patterns)

Flags code constructs indicating potential vulnerabilities:

- Dynamic code execution — injection vectors
- DOM sinks (innerHTML, outerHTML, document write operations) — XSS vectors
- Cookie access — session theft surface
- Location manipulation — open redirect candidates
- Cross-origin messaging (postMessage/message listeners)
- Prototype pollution vectors
- Framework-specific unsafe HTML handling
- CORS configuration patterns
- JSONP usage

## Output

Results save to `./js-analysis/` (or custom path with `-o`):

```
js-analysis/
├── analysis.json    # Full structured results with metadata
├── endpoints.txt    # API endpoints (one per line)
├── params.txt       # Query parameters discovered
├── domains.txt      # Referenced domains
└── report.md        # Markdown report (with --report)
```

### Pipeline Integration

```bash
# Feed endpoints into ffuf for fuzzing
js-surgeon https://target.com
cat js-analysis/endpoints.txt | while read ep; do
  ffuf -u "https://target.com${ep}" -w /dev/null -mc all
done

# Parse high-confidence secrets
cat js-analysis/analysis.json | jq '.secrets[] | select(.confidence > 70) | "\(.type): \(.value)"'

# Extract query params for parameter fuzzing
cat js-analysis/params.txt | sort -u > params_wordlist.txt

# Deep analysis with report generation
js-surgeon https://target.com --deep --report -o ./target-js-analysis

# Chain with ghost-recon — analyze JS on discovered subdomains
cat subdomains.txt | while read sub; do
  js-surgeon "https://$sub" -o "js-results/$sub"
done
```

## Changelog

### v2.0.0
- Added entropy-based confidence scoring for secrets (0-100%)
- Added framework detection with version extraction
- Added source map discovery and validation
- Added `--deep` mode for webpack chunk following
- Added query parameter extraction
- Added developer comment mining
- Added sensitive path detection
- Added `--report` for markdown report generation
- Expanded secret patterns from 16 to 40+
- Expanded security patterns from 17 to 30+
- Added severity levels (critical/high/medium/low)
- Added threading support with `-t` flag
- Added multiple output files (endpoints, params, domains)

### v1.0.0
- Initial release with core extraction capabilities

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Only analyze JavaScript from applications you have explicit permission to test. The author assumes no liability for misuse.

## License

MIT
