# Security Implementation Documentation

This document describes the security features implemented in this WordPress reconnaissance tool, their dependencies, and associated risks.

---

## Security Features Implemented

### 1. SSRF Protection (`core/ssrf_protection.py`)

**Purpose**: Prevent Server-Side Request Forgery attacks when scanning internal infrastructure.

**Blocked Ranges**:
| Range | Description | Risk |
|-------|-------------|------|
| `10.0.0.0/8` | RFC 1918 Private Class A | Internal network access |
| `172.16.0.0/12` | RFC 1918 Private Class B | Internal network access |
| `192.168.0.0/16` | RFC 1918 Private Class C | Internal network access |
| `127.0.0.0/8` | Loopback | Localhost access |
| `169.254.0.0/16` | Link-local | Cloud metadata exposure |
| `0.0.0.0/8` | Current network | Network spoofing |
| `169.254.169.254` | AWS/GCP/Azure metadata | Credential theft |
| `100.100.100.200` | Alibaba Cloud metadata | Credential theft |

**Functions**:
- `is_safe_target(host, port)` - Check if target is in blocklist
- `validate_safe_url(url)` - Validate URL for SSRF
- `is_safe_url(url)` - Non-throwing version
- `sanitize_target_for_logging(target)` - Redact sensitive data

**Dependencies**: `ipaddress`, `socket`, `urllib.parse`

**Risks Mitigated**:
- Internal network scanning via pingback SSRF
- Cloud metadata credential theft
- Localhost service exploitation

---

### 2. Rate Limiting (`utils/rate_limiter.py`)

**Purpose**: Prevent account lockouts and WAF/IPS detection during brute-force operations.

**Configuration**:
| Parameter | Value | Description |
|-----------|-------|-------------|
| `max_requests` | 5 | Requests per interval |
| `per_seconds` | 1.0 | Interval in seconds |
| `backoff_factor` | 2.0 | Exponential backoff multiplier |
| `max_retries` | 3 | Retry attempts |
| `max_consecutive_failures` | 3 | Skip threshold |

**Classes**:
- `RateLimiter` - Token bucket rate limiter
- `RetryLimiter` - Rate limiter with retry logic

**Dependencies**: `asyncio`, `time`

**Risks Mitigated**:
- Account lockouts during credential brute-forcing
- WAF/IPS detection
- Server overload

---

### 3. Subprocess Security (`base/tool.py`)

**Purpose**: Safe execution of external tools (wpscan, nuclei, etc.)

**Security Measures**:
| Feature | Implementation |
|---------|----------------|
| Shell Injection | `shell=False` enforced |
| Argument Sanitization | Dangerous chars replaced |
| Binary Verification | `shutil.which()` before execution |
| Timeout | 600s default, configurable |
| Sensitive Data Redaction | Regex-based credential redaction |

**Functions**:
- `_sanitize_arg(arg)` - Remove dangerous characters
- `_redact_sensitive_from_output(output)` - Redact API keys, tokens, passwords

**Dependencies**: `subprocess`, `shutil`, `re`

**Risks Mitigated**:
- Shell command injection
- Credential exposure in logs
- Tool hanging indefinitely

---

### 4. Safe XML Parsing (`utils/xml_parser.py`)

**Purpose**: Prevent XXE and XML-based attacks in XML-RPC responses.

**Security Measures**:
| Feature | Implementation |
|---------|----------------|
| XXE Prevention | `xml.etree.ElementTree` (no external entities) |
| Safe Parsing | Restricted mode, no DTD |
| Error Handling | Graceful degradation on malformed XML |

**Functions**:
- `safe_parse_xml(xml_string)` - Parse without XXE
- `parse_xmlrpc_response(content)` - Extract response data safely
- `extract_fault_code(content)` - Safe fault code extraction
- `is_xmlrpc_success(content)` - Check success state

**Dependencies**: `xml.etree.ElementTree`

**Risks Mitigated**:
- XML External Entity (XXE) injection
- Billion laughs (entity expansion DoS)
- Local file inclusion via XML

---

### 5. TLS Verification Control (`config.py`, `runner.py`, `http_client.py`)

**Purpose**: Control TLS certificate verification.

**Implementation**:
- `Config.insecure` flag
- `--insecure` CLI argument
- Propagated to `HttpClient` and `httpx.AsyncClient`

**Dependencies**: `httpx`

**Risks**:
- **WARNING**: Disabling TLS verification exposes traffic to MITM attacks
- Only use `--insecure` for testing with self-signed certificates

---

### 6. User-Agent Rotation (`core/http_client.py`)

**Purpose**: Avoid simple WAF/IPS detection.

**Implementation**:
- List of 5 common browser User-Agents
- Rotation on each request
- `get_random_user_agent()` for custom selection

**Dependencies**: `random`, `httpx`

**Risks Mitigated**:
- Simple bot detection
- WAF fingerprinting

---

### 7. Target URL Validation (`core/target.py`)

**Purpose**: Ensure only valid, safe URLs are accepted.

**Validation**:
- Auto-prepend `https://` if missing
- Domain format validation
- Scheme whitelist (http, https only)

**Dependencies**: `urllib.parse`, `re`

**Risks Mitigated**:
- Invalid URL injection
- Scheme confusion attacks

---

## Security Architecture Diagram

```
User Input (URL, --insecure, wordlist)
         │
         ▼
   Target Validation (core/target.py)
         │
         ▼
   Runner Orchestration (base/runner.py)
         │
         ├──► HttpClient ──► User-Agent Rotation ──► TLS Verification
         │
         ├──► Steps
         │     │
         │     ├──► SSRF Protection (core/ssrf_protection.py)
         │     │         │
         │     │         ▼
         │     │    is_safe_target() ──► Block internal IPs
         │     │
         │     ├──► Rate Limiting (utils/rate_limiter.py)
         │     │         │
         │     │         ▼
         │     │    RetryLimiter ──► 5 req/sec, exponential backoff
         │     │
         │     ├──► Safe XML Parsing (utils/xml_parser.py)
         │     │         │
         │     │         ▼
         │     │    ET.fromstring() ──► No XXE
         │     │
         │     └──► Tool Execution (base/tool.py)
         │               │
         │               ▼
         │        shell=False, sanitization, redaction
         │
         ▼
   Findings with sanitized evidence
```

---

## Risk Assessment

### High Risk Operations

| Operation | Risk | Mitigation | Residual Risk |
|-----------|------|------------|---------------|
| Credential Brute Force | Account lockout | Rate limiting (5/sec) | Medium |
| XML-RPC SSRF | Internal network scan | SSRF blocklist | Low |
| External Tool Execution | Shell injection | shell=False, sanitization | Low |
| TLS Verification Disabled | MITM attack | Warning in CLI | User responsibility |

### Residual Risks

1. **Credential Storage**: Wordlists may contain sensitive data
   - **Mitigation**: Wordlists excluded from git, must be provided externally

2. **SSRF False Negatives**: Unknown internal ranges may be accessible
   - **Mitigation**: Blocklist approach, explicit allowlist for known safe targets

3. **Rate Limiting Bypass**: Tools may not respect rate limits
   - **Mitigation**: Rate limiter is application-level, not protocol-level

4. **XXE in Dependencies**: Third-party libraries may have XXE
   - **Mitigation**: Using stdlib `xml.etree.ElementTree` (no external entities by default)

---

## Dependencies Summary

| Module | External Dependencies | Security Notes |
|--------|----------------------|----------------|
| `core/ssrf_protection.py` | stdlib only | No external dependencies |
| `utils/rate_limiter.py` | stdlib only | asyncio-based, safe |
| `base/tool.py` | stdlib only | subprocess wrapper |
| `utils/xml_parser.py` | stdlib only | xml.etree.ElementTree |
| `core/http_client.py` | httpx | verify parameter controls TLS |
| `core/target.py` | stdlib only | URL parsing only |

---

## Configuration Security

### Safe Defaults
```python
Config(
    threads=2,        # Conservative threading
    timeout=10,       # 10s request timeout
    insecure=False,   # TLS verification ON
    keys={},          # No hardcoded keys
)
```

### Rate Limiting
```python
RetryLimiter(
    max_requests=5,                 # 5 requests/second
    per_seconds=1.0,
    backoff_factor=2.0,             # 1s, 2s, 4s backoff
    max_retries=3,
    max_consecutive_failures=3,     # Skip after 3 failures
)
```

---

## Testing Recommendations

1. **SSRF Tests**:
   - Verify blocklist blocks all private ranges
   - Test cloud metadata IPs (169.254.169.254)
   - Test IPv6 addresses

2. **Rate Limiting Tests**:
   - Verify 5 req/sec limit is enforced
   - Verify exponential backoff triggers
   - Verify skip after 3 consecutive failures

3. **XML Parsing Tests**:
   - Send XXE payload, verify no file access
   - Send billion laughs, verify timeout

4. **Tool Execution Tests**:
   - Send shell metacharacters, verify sanitization
   - Verify no credentials in output logs
