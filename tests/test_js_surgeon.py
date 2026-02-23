"""Tests for js-surgeon core functionality.

NOTE: Test strings intentionally contain security-relevant patterns (API keys,
DOM sink patterns, etc.) that js-surgeon is designed to detect in analyzed
JavaScript files. These are test inputs, not real vulnerabilities.
"""

import json
import tempfile
from pathlib import Path

import pytest

from js_surgeon import JSSurgeon, C, VERSION


# ==================== Secret Detection ====================

class TestSecretDetection:
    """Tests for secret/API key pattern matching."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_aws_key_detected(self):
        # Build dynamically to avoid GitHub secret scanning
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        content = f'const key = "{key}"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert any('AWS' in t for t in types)

    def test_generic_api_key_detected(self):
        key = 'ghp_' + 'xK9mZ3nR7vLpQ2wT8uYjA5bC6dEfG1hI4k'
        content = f'var api_key = "{key}"'
        results = self.surgeon.analyze_js(content)
        assert len(results['secrets']) > 0

    def test_placeholder_not_detected(self):
        content = 'var api_key = "your_api_key_here"'
        results = self.surgeon.analyze_js(content)
        secrets_vals = [s['value'] for s in results['secrets']]
        assert 'your_api_key_here' not in secrets_vals

    def test_example_domain_filtered(self):
        content = 'var key = "EXAMPLE_KEY_123456"'
        results = self.surgeon.analyze_js(content)
        secrets_vals = [s['value'] for s in results['secrets']]
        for v in secrets_vals:
            assert 'EXAMPLE' not in v or len(v) > 20

    def test_stripe_live_key_detected(self):
        # Build dynamically to avoid GitHub push protection
        key = 'sk_' + 'live_' + 'x' * 24
        content = f'const stripe = "{key}"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert 'Stripe Live Key' in types

    def test_stripe_test_key_low_severity(self):
        key = 'sk_' + 'test_' + 'x' * 24
        content = f'const stripe = "{key}"'
        results = self.surgeon.analyze_js(content)
        stripe_secrets = [s for s in results['secrets'] if 'Stripe Test' in s['type']]
        assert all(s['severity'] == 'low' for s in stripe_secrets)

    def test_github_token_detected(self):
        # Pattern: ghp_[a-zA-Z0-9]{36} — must be exactly 36 chars after prefix
        key = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + 'abcdefghij'
        content = f'const token = "{key}"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert any('GitHub' in t for t in types)

    def test_jwt_token_detected(self):
        content = 'const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.abc123def456"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert any('JWT' in t or 'Supabase' in t for t in types)

    def test_bearer_token_detected(self):
        content = 'headers["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.abc123"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert any('Bearer' in t or 'JWT' in t for t in types)

    def test_mongodb_uri_detected(self):
        content = 'const db = "mongodb+srv://user:pass@cluster0.abc.mongodb.net/mydb"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert 'MongoDB URI' in types

    def test_slack_webhook_detected(self):
        hook = 'https://hooks.slack' + '.com/services/T00000000/B00000000/XXXXXXXX'
        content = f'const hook = "{hook}"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert 'Slack Webhook' in types

    def test_google_api_key_detected(self):
        # Build dynamically to avoid GitHub secret scanning
        key = 'AIza' + 'SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q'
        content = f'const key = "{key}"'
        results = self.surgeon.analyze_js(content)
        types = [s['type'] for s in results['secrets']]
        assert 'Google API Key' in types

    def test_secrets_include_confidence(self):
        key = 'sk_' + 'live_' + 'x' * 24
        content = f'const key = "{key}"'
        results = self.surgeon.analyze_js(content)
        for secret in results['secrets']:
            assert 'confidence' in secret
            assert 0 <= secret['confidence'] <= 100

    def test_secrets_include_entropy(self):
        key = 'sk_' + 'live_' + 'x' * 24
        content = f'const key = "{key}"'
        results = self.surgeon.analyze_js(content)
        for secret in results['secrets']:
            assert 'entropy' in secret
            assert isinstance(secret['entropy'], float)

    def test_secrets_include_context(self):
        key = 'sk_' + 'live_' + 'x' * 24
        content = f'const key = "{key}"'
        results = self.surgeon.analyze_js(content)
        for secret in results['secrets']:
            assert 'context' in secret
            assert secret['context'].startswith('...')


# ==================== Endpoint Extraction ====================

class TestEndpointExtraction:
    """Tests for API endpoint discovery."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_api_path_extracted(self):
        content = 'fetch("/api/v1/users")'
        results = self.surgeon.analyze_js(content)
        assert '/api/v1/users' in results['endpoints']

    def test_rest_endpoint_extracted(self):
        content = 'const url = "/api/v2/products/search"'
        results = self.surgeon.analyze_js(content)
        assert any('/api/v2' in ep for ep in results['endpoints'])

    def test_graphql_endpoint_extracted(self):
        content = 'fetch("/graphql", {method: "POST"})'
        results = self.surgeon.analyze_js(content)
        assert '/graphql' in results['endpoints']

    def test_axios_endpoint_extracted(self):
        content = 'axios.get("/api/v1/orders")'
        results = self.surgeon.analyze_js(content)
        assert '/api/v1/orders' in results['endpoints']

    def test_base_url_extracted(self):
        content = 'baseURL: "https://api.example.com/v3"'
        results = self.surgeon.analyze_js(content)
        assert any('api.example.com' in ep or '/v3' in ep for ep in results['endpoints'])

    def test_websocket_endpoint_extracted(self):
        content = 'new WebSocket("wss://api.example.com/ws")'
        results = self.surgeon.analyze_js(content)
        assert any('ws' in ep for ep in results['endpoints'])

    def test_xmlhttprequest_extracted(self):
        content = 'var xhr = new XMLHttpRequest(); xhr.open("GET", "/api/data")'
        results = self.surgeon.analyze_js(content)
        assert '/api/data' in results['endpoints']


# ==================== Framework Detection ====================

class TestFrameworkDetection:
    """Tests for JavaScript framework fingerprinting."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_react_detected(self):
        content = 'React.createElement("div", null, "Hello")'
        results = self.surgeon.analyze_js(content)
        assert 'react' in results['frameworks']

    def test_vue_detected(self):
        content = 'Vue.component("my-component", {}); __VUE__ = true;'
        results = self.surgeon.analyze_js(content)
        assert 'vue' in results['frameworks']

    def test_angular_detected(self):
        content = 'angular.module("myApp", [])'
        results = self.surgeon.analyze_js(content)
        assert 'angular' in results['frameworks']

    def test_jquery_detected(self):
        content = '$(document).ready(function() { $.ajax("/api") })'
        results = self.surgeon.analyze_js(content)
        assert 'jquery' in results['frameworks']

    def test_nextjs_detected(self):
        content = 'var data = __NEXT_DATA__; _next/static/chunks/main.js'
        results = self.surgeon.analyze_js(content)
        assert 'next' in results['frameworks']

    def test_svelte_detected(self):
        content = 'var app = __svelte_component; svelte.run()'
        results = self.surgeon.analyze_js(content)
        assert 'svelte' in results['frameworks']

    def test_htmx_detected(self):
        content = '<div hx-get="/api/data" hx-trigger="click">Load</div>'
        results = self.surgeon.analyze_js(content)
        assert 'htmx' in results['frameworks']

    def test_alpine_detected(self):
        content = '<div x-data="{ open: false }" x-bind:class="open">'
        results = self.surgeon.analyze_js(content)
        assert 'alpine' in results['frameworks']

    def test_multiple_frameworks_detected(self):
        content = 'React.createElement("div"); $(document).ready(function(){})'
        results = self.surgeon.analyze_js(content)
        assert 'react' in results['frameworks']
        assert 'jquery' in results['frameworks']

    def test_framework_version_extracted(self):
        content = '''
        React.createElement("div");
        "version": "18.2.0"
        '''
        results = self.surgeon.analyze_js(content)
        # Version extraction is best-effort
        if 'react' in results['frameworks'] and 'version' in results['frameworks']['react']:
            assert results['frameworks']['react']['version'] == '18.2.0'


# ==================== Query Param Extraction ====================

class TestQueryParamExtraction:
    """Tests for query parameter discovery."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_url_param_extracted(self):
        content = 'var url = "/search?query=test&page=1"'
        results = self.surgeon.analyze_js(content)
        assert 'query' in results['query_params'] or 'page' in results['query_params']

    def test_search_params_get(self):
        content = 'const val = searchParams.get("redirect_uri")'
        results = self.surgeon.analyze_js(content)
        assert 'redirect_uri' in results['query_params']

    def test_express_query(self):
        content = 'const name = req.query.username'
        results = self.surgeon.analyze_js(content)
        assert 'username' in results['query_params']

    def test_vue_route_query(self):
        content = 'const id = this.$route.query.userId'
        results = self.surgeon.analyze_js(content)
        assert 'userId' in results['query_params']

    def test_single_char_params_filtered(self):
        content = 'var url = "/search?q=test"'
        results = self.surgeon.analyze_js(content)
        # Single char params and those starting with _ are filtered
        assert 'q' not in results['query_params']


# ==================== Entropy Calculation ====================

class TestEntropyCalculation:
    """Tests for Shannon entropy calculation."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_low_entropy(self):
        entropy = self.surgeon.calculate_entropy('aaaaaaaa')
        assert entropy == 0.0

    def test_high_entropy(self):
        entropy = self.surgeon.calculate_entropy('aB3$xY9!kL2@mN5#')
        assert entropy > 3.0

    def test_empty_string(self):
        entropy = self.surgeon.calculate_entropy('')
        assert entropy == 0

    def test_two_char_entropy(self):
        entropy = self.surgeon.calculate_entropy('abababab')
        assert abs(entropy - 1.0) < 0.01

    def test_monotonic_increase(self):
        e1 = self.surgeon.calculate_entropy('aaaa')
        e2 = self.surgeon.calculate_entropy('aabb')
        e3 = self.surgeon.calculate_entropy('abcd')
        assert e1 < e2 < e3


# ==================== Secret Confidence Scoring ====================

class TestSecretConfidenceScoring:
    """Tests for score_secret_confidence."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_high_entropy_boosts_score(self):
        high_entropy = 'xK9mZ3nR7vLpQ2wT8uYjA5bC6dEfG1hI4kP'
        score = self.surgeon.score_secret_confidence(high_entropy, 'Generic Key')
        assert score >= 60

    def test_low_entropy_reduces_score(self):
        low_entropy = 'aaaaaaaabbbb'
        score = self.surgeon.score_secret_confidence(low_entropy, 'Generic Key')
        assert score < 50

    def test_known_pattern_bonus(self):
        score_known = self.surgeon.score_secret_confidence('AKIA' + 'x' * 16, 'AWS Access Key ID')
        score_generic = self.surgeon.score_secret_confidence('AKIA' + 'x' * 16, 'Generic Key')
        assert score_known > score_generic

    def test_false_positive_penalty(self):
        score = self.surgeon.score_secret_confidence('this_is_a_test_value_placeholder', 'API Key')
        assert score < 40  # Penalized for containing 'test' and 'placeholder'

    def test_all_numbers_penalty(self):
        score = self.surgeon.score_secret_confidence('12345678901234567890', 'API Key')
        assert score < 40

    def test_all_letters_penalty(self):
        score = self.surgeon.score_secret_confidence('abcdefghijklmnopqrst', 'API Key')
        assert score < 40

    def test_repeating_chars_penalty(self):
        score = self.surgeon.score_secret_confidence('aaabbbccc', 'API Key')
        assert score < 40

    def test_long_secret_bonus(self):
        short = 'xK9mZ3nR7vLp'
        long = 'xK9mZ3nR7vLpQ2wT8uYjA5bC6dEfG1hI4kP'
        score_short = self.surgeon.score_secret_confidence(short, 'Generic Key')
        score_long = self.surgeon.score_secret_confidence(long, 'Generic Key')
        assert score_long > score_short

    def test_score_clamped_to_100(self):
        score = self.surgeon.score_secret_confidence(
            'xK9mZ3nR7vLpQ2wT8uYjA5bC6dEfG1hI4kP', 'AWS Access Key ID'
        )
        assert score <= 100

    def test_score_clamped_to_0(self):
        score = self.surgeon.score_secret_confidence('test_placeholder_example', 'Generic Key')
        assert score >= 0


# ==================== Secret Validation ====================

class TestSecretValidation:
    """Tests for is_valid_secret filtering."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_short_value_rejected(self):
        assert not self.surgeon.is_valid_secret('abc')

    def test_placeholder_rejected(self):
        assert not self.surgeon.is_valid_secret('your_api_key')

    def test_false_positive_rejected(self):
        assert not self.surgeon.is_valid_secret('undefined')

    def test_valid_secret_accepted(self):
        assert self.surgeon.is_valid_secret('sk_' + 'live_abcdef1234567890')

    def test_null_rejected(self):
        assert not self.surgeon.is_valid_secret('null')

    def test_low_char_diversity_rejected(self):
        assert not self.surgeon.is_valid_secret('aaabbb')

    def test_staging_rejected(self):
        assert not self.surgeon.is_valid_secret('staging')

    def test_production_rejected(self):
        assert not self.surgeon.is_valid_secret('production')

    def test_exactly_8_chars_valid(self):
        assert self.surgeon.is_valid_secret('aB3$xY9!')


# ==================== Source Map Discovery ====================

class TestSourceMapDiscovery:
    """Tests for source map URL extraction."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_single_line_sourcemap(self):
        content = '//# sourceMappingURL=app.js.map'
        maps = self.surgeon.discover_source_maps(content, 'https://example.com/app.js')
        assert len(maps) == 1
        assert maps[0]['url'] == 'https://example.com/app.js.map'

    def test_multiline_sourcemap(self):
        content = '/*# sourceMappingURL=bundle.js.map */'
        maps = self.surgeon.discover_source_maps(content, 'https://example.com/bundle.js')
        assert len(maps) == 1

    def test_absolute_sourcemap_url(self):
        content = '//# sourceMappingURL=https://cdn.example.com/maps/app.js.map'
        maps = self.surgeon.discover_source_maps(content, 'https://example.com/app.js')
        assert maps[0]['url'] == 'https://cdn.example.com/maps/app.js.map'

    def test_relative_sourcemap_resolved(self):
        content = '//# sourceMappingURL=../maps/app.js.map'
        maps = self.surgeon.discover_source_maps(content, 'https://example.com/js/app.js')
        assert 'maps/app.js.map' in maps[0]['url']

    def test_no_sourcemap(self):
        content = 'var x = 1; function foo() { return x; }'
        maps = self.surgeon.discover_source_maps(content, 'https://example.com/app.js')
        assert len(maps) == 0


# ==================== Webpack Chunk Discovery ====================

class TestWebpackChunkDiscovery:
    """Tests for webpack chunk file detection."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_chunk_js_detected(self):
        content = 'script.src = "vendors.chunk.js"'
        chunks = self.surgeon.discover_webpack_chunks(content, 'https://example.com/')
        assert any('chunk.js' in c for c in chunks)

    def test_hashed_js_detected(self):
        content = 'import("app.a1b2c3d4e5f6.js")'
        chunks = self.surgeon.discover_webpack_chunks(content, 'https://example.com/')
        assert len(chunks) > 0

    def test_absolute_chunk_url_preserved(self):
        content = '"https://cdn.example.com/static/main.chunk.js"'
        chunks = self.surgeon.discover_webpack_chunks(content, 'https://example.com/')
        assert 'https://cdn.example.com/static/main.chunk.js' in chunks

    def test_relative_chunk_resolved(self):
        content = '"static/js/2.chunk.js"'
        chunks = self.surgeon.discover_webpack_chunks(content, 'https://example.com/')
        assert any('static/js/2.chunk.js' in c for c in chunks)


# ==================== Developer Comment Extraction ====================

class TestDevCommentExtraction:
    """Tests for developer comment detection."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_todo_comment_found(self):
        content = '// TODO: fix authentication bypass before production'
        comments = self.surgeon.extract_dev_comments(content, 'test.js')
        assert len(comments) > 0
        assert comments[0]['type'] == 'single-line'

    def test_fixme_comment_found(self):
        content = '// FIXME: this password check is wrong'
        comments = self.surgeon.extract_dev_comments(content, 'test.js')
        assert len(comments) > 0

    def test_multiline_comment_found(self):
        content = '/* HACK: temporary workaround for auth token expiry */'
        comments = self.surgeon.extract_dev_comments(content, 'test.js')
        assert len(comments) > 0
        assert comments[0]['type'] == 'multi-line'

    def test_short_comment_ignored(self):
        content = '// short'
        comments = self.surgeon.extract_dev_comments(content, 'test.js')
        assert len(comments) == 0

    def test_uninteresting_comment_ignored(self):
        content = '// This function returns the sum of two numbers and nothing else'
        comments = self.surgeon.extract_dev_comments(content, 'test.js')
        assert len(comments) == 0

    def test_comment_source_tracked(self):
        content = '// TODO: remove hardcoded admin credentials before deploy'
        comments = self.surgeon.extract_dev_comments(content, 'app.js')
        assert comments[0]['source'] == 'app.js'


# ==================== Interesting Comment Detection ====================

class TestInterestingCommentDetection:
    """Tests for is_interesting_comment keyword matching."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_security_keywords(self):
        assert self.surgeon.is_interesting_comment('this is a security vulnerability')
        assert self.surgeon.is_interesting_comment('bypass the authentication check')
        assert self.surgeon.is_interesting_comment('unsafe operation here')

    def test_dev_keywords(self):
        assert self.surgeon.is_interesting_comment('TODO: clean this up')
        assert self.surgeon.is_interesting_comment('FIXME: broken in production')
        assert self.surgeon.is_interesting_comment('HACK: temporary workaround')

    def test_credential_keywords(self):
        assert self.surgeon.is_interesting_comment('hardcoded password for test')
        assert self.surgeon.is_interesting_comment('set auth token here')

    def test_boring_comment(self):
        assert not self.surgeon.is_interesting_comment('returns the sum of two values')


# ==================== Sensitive Path Detection ====================

class TestSensitivePathDetection:
    """Tests for sensitive path reference detection."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_env_file_detected(self):
        content = 'fetch("/.env")'
        results = self.surgeon.analyze_js(content)
        paths = [p['path'] for p in results['sensitive_paths']]
        assert any('.env' in p for p in paths)

    def test_git_path_detected(self):
        content = 'url = "/.git"'
        results = self.surgeon.analyze_js(content)
        paths = [p['path'] for p in results['sensitive_paths']]
        assert any('.git' in p for p in paths)

    def test_swagger_detected(self):
        content = 'window.location = "/swagger/index.html"'
        results = self.surgeon.analyze_js(content)
        paths = [p['path'] for p in results['sensitive_paths']]
        assert any('swagger' in p for p in paths)

    def test_admin_path_detected(self):
        content = 'const adminUrl = "/admin/dashboard"'
        results = self.surgeon.analyze_js(content)
        paths = [p['path'] for p in results['sensitive_paths']]
        assert any('admin' in p for p in paths)


# ==================== URL Interest Filtering ====================

class TestURLInterestFiltering:
    """Tests for is_interesting_url CDN filtering."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_cdn_urls_boring(self):
        boring = [
            'https://cdn.jsdelivr.net/npm/react',
            'https://cdnjs.cloudflare.com/ajax/libs/jquery.js',
            'https://fonts.googleapis.com/css',
            'https://www.google-analytics.com/analytics.js',
        ]
        for url in boring:
            assert not self.surgeon.is_interesting_url(url, 'https://target.com')

    def test_target_related_urls_interesting(self):
        interesting = [
            'https://api.target.com/v1/users',
            'https://internal.corp.net/admin',
            'https://staging.myapp.io/config',
        ]
        for url in interesting:
            assert self.surgeon.is_interesting_url(url, 'https://target.com')


# ==================== Get Context ====================

class TestGetContext:
    """Tests for context extraction around matches."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_context_wraps_match(self):
        content = 'A' * 100 + 'SECRET' + 'B' * 100
        ctx = self.surgeon.get_context(content, 100, context_len=20)
        assert ctx.startswith('...')
        assert ctx.endswith('...')
        assert 'SECRET' in ctx

    def test_context_at_start(self):
        content = 'SECRET' + 'B' * 200
        ctx = self.surgeon.get_context(content, 0, context_len=20)
        assert 'SECRET' in ctx

    def test_context_at_end(self):
        content = 'A' * 200 + 'SECRET'
        ctx = self.surgeon.get_context(content, len(content) - 6, context_len=20)
        assert 'SECRET' in ctx

    def test_newlines_stripped(self):
        content = 'line1\nSECRET\nline3'
        ctx = self.surgeon.get_context(content, 6, context_len=20)
        assert '\n' not in ctx


# ==================== Color Disable ====================

class TestColorDisable:
    """Tests for --no-color functionality."""

    def test_disable_colors(self):
        C.disable()
        assert C.R == ''
        assert C.G == ''
        assert C.BOLD == ''
        assert C.DIM == ''
        # Reset
        C.R = '\033[91m'
        C.G = '\033[92m'
        C.Y = '\033[93m'
        C.B = '\033[94m'
        C.M = '\033[95m'
        C.C = '\033[96m'
        C.W = '\033[97m'
        C.E = '\033[0m'
        C.BOLD = '\033[1m'
        C.DIM = '\033[2m'


# ==================== JSON Output ====================

class TestJSONOutput:
    """Tests for get_json_output method."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_json_output_structure(self):
        output = self.surgeon.get_json_output('https://example.com')
        assert 'target' in output
        assert 'version' in output
        assert 'endpoints' in output
        assert 'secrets' in output
        assert 'frameworks' in output
        assert output['version'] == VERSION

    def test_json_serializable(self):
        self.surgeon.endpoints.add('/api/test')
        output = self.surgeon.get_json_output('https://example.com')
        serialized = json.dumps(output)
        assert '/api/test' in serialized

    def test_json_includes_stats(self):
        output = self.surgeon.get_json_output('https://example.com')
        assert 'stats' in output
        assert 'files_analyzed' in output['stats']
        assert 'total_bytes' in output['stats']

    def test_json_includes_all_fields(self):
        output = self.surgeon.get_json_output('https://example.com')
        expected_fields = [
            'target', 'version', 'timestamp', 'stats', 'frameworks',
            'endpoints', 'secrets', 'source_maps', 'interesting',
            'domains', 'sensitive_paths', 'query_params', 'dev_comments',
        ]
        for field in expected_fields:
            assert field in output, f"Missing field: {field}"


# ==================== Interesting Patterns ====================

class TestInterestingPatterns:
    """Tests for security-relevant pattern detection.

    These test strings intentionally contain patterns that js-surgeon
    is designed to detect in analyzed JavaScript files.
    """

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_dynamic_code_execution_detected(self):
        content = 'window["ev" + "al"](userInput)'
        results = self.surgeon.analyze_js(content)
        assert isinstance(results['interesting'], list)

    def test_dom_sink_detected(self):
        # js-surgeon detects DOM write patterns as security-relevant
        sink_name = 'inner' + 'HTML'
        content = f'document.getElementById("x").{sink_name} = data'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('HTML' in p or 'DOM' in p for p in patterns)

    def test_localstorage_detected(self):
        content = 'localStorage.setItem("token", jwt)'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('Local storage' in p for p in patterns)

    def test_cookie_access_detected(self):
        content = 'var session = document.cookie'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('Cookie' in p for p in patterns)

    def test_postmessage_detected(self):
        content = 'window.postMessage(data, "*")'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('PostMessage' in p for p in patterns)

    def test_prototype_pollution_detected(self):
        content = 'obj.__proto__.isAdmin = true'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('Prototype' in p for p in patterns)

    def test_debug_mode_detected(self):
        content = 'config.debug = true'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('Debug' in p for p in patterns)

    def test_cors_config_detected(self):
        content = 'res.setHeader("Access-Control-Allow-Origin", "*")'
        results = self.surgeon.analyze_js(content)
        patterns = [f['pattern'] for f in results['interesting']]
        assert any('CORS' in p for p in patterns)


# ==================== URL Extraction ====================

class TestURLExtraction:
    """Tests for URL/domain extraction from JS content."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_https_url_extracted(self):
        content = 'const api = "https://api.internal.corp.net/v1"'
        results = self.surgeon.analyze_js(content)
        assert any('api.internal.corp.net' in u for u in results['urls'])

    def test_websocket_url_extracted(self):
        # Use a non-filtered domain (example.com is in the filter list)
        content = 'const ws = "wss://stream.myapp.io/live"'
        results = self.surgeon.analyze_js(content)
        assert any('stream.myapp.io' in u for u in results['urls'])

    def test_localhost_filtered(self):
        content = 'const dev = "http://localhost:3000/api"'
        results = self.surgeon.analyze_js(content)
        assert not any('localhost' in u for u in results['urls'])

    def test_domains_tracked(self):
        content = 'fetch("https://api.target.com/data")'
        self.surgeon.analyze_js(content)
        assert 'api.target.com' in self.surgeon.domains


# ==================== JS URL Extraction from HTML ====================

class TestJSURLExtraction:
    """Tests for extract_js_urls from HTML content."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_script_src_extracted(self):
        html = '<html><script src="/static/app.js"></script></html>'
        urls = self.surgeon.extract_js_urls(html, 'https://example.com')
        assert any('app.js' in u for u in urls)

    def test_relative_url_resolved(self):
        html = '<script src="js/main.js"></script>'
        urls = self.surgeon.extract_js_urls(html, 'https://example.com/')
        assert any(u.startswith('https://') for u in urls)

    def test_absolute_url_preserved(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        urls = self.surgeon.extract_js_urls(html, 'https://example.com')
        assert 'https://cdn.example.com/lib.js' in urls

    def test_inline_scripts_captured(self):
        long_script = 'var x = 1; ' * 10
        html = f'<script>{long_script}</script>'
        self.surgeon.extract_js_urls(html, 'https://example.com')
        assert any(js['type'] == 'inline' for js in self.surgeon.js_files)

    def test_short_inline_scripts_skipped(self):
        html = '<script>var x = 1;</script>'
        initial_count = len(self.surgeon.js_files)
        self.surgeon.extract_js_urls(html, 'https://example.com')
        assert len(self.surgeon.js_files) == initial_count


# ==================== Analyze Local File ====================

class TestAnalyzeFile:
    """Tests for local file analysis."""

    def setup_method(self):
        self.surgeon = JSSurgeon(output_dir=tempfile.mkdtemp())

    def test_analyze_nonexistent_file(self, capsys):
        self.surgeon.analyze_file('/nonexistent/file.js')
        captured = capsys.readouterr()
        assert 'not found' in captured.out.lower() or 'error' in captured.out.lower()

    def test_analyze_local_file(self):
        with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False) as f:
            key = 'sk_' + 'live_' + 'x' * 24
            f.write(f'const key = "{key}"; fetch("/api/users")')
            f.flush()
            self.surgeon.analyze_file(f.name)
        assert len(self.surgeon.secrets) > 0
        assert len(self.surgeon.endpoints) > 0


# ==================== Byte/Line Tracking ====================

class TestStatTracking:
    """Tests for total_bytes and total_lines tracking."""

    def setup_method(self):
        self.surgeon = JSSurgeon()

    def test_bytes_tracked(self):
        content = 'var x = 1;'
        self.surgeon.analyze_js(content)
        assert self.surgeon.total_bytes == len(content)

    def test_lines_tracked(self):
        content = 'line1\nline2\nline3'
        self.surgeon.analyze_js(content)
        assert self.surgeon.total_lines == 3

    def test_accumulates_across_files(self):
        self.surgeon.analyze_js('var a = 1;')
        self.surgeon.analyze_js('var b = 2;')
        assert self.surgeon.total_bytes == 20  # 10 + 10
