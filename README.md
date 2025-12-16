# Domain Accessibility Checker with Enhanced Cloudflare Detection

![Python Code Checks](https://github.com/dendi-pradigta/cloudflare-domain-validator/actions/workflows/python-checks.yml/badge.svg)

A Python tool to check domain accessibility (DNS, HTTP/HTTPS, TLS) with multi-method Cloudflare detection for security audits.

## Features

### Enhanced Cloudflare Detection
- **IP Range Matching**: Detects Cloudflare IPv4 ranges
- **CNAME Pattern Matching**: Detects `.cdn.cloudflare.net`, `.cloudflare.net`, `.cloudflare.com` patterns
- **HTTP Header Analysis**: Detects Cloudflare headers (`CF-Ray`, `Server: cloudflare`, `CF-Cache-Status`, etc.)
- **Confidence Scoring**: High/Medium/Low confidence levels based on detection methods

### Domain Checking Capabilities
- DNS resolution (IPs & CNAMEs)
- TCP connectivity on ports 80 & 443
- HTTP/HTTPS status codes and redirect detection
- TLS certificate validation and expiry
- Parallel domain checking (3 workers)

### Reliability Features
- Configurable timeouts (connect, read)
- Retry logic for failed connections
- Comprehensive error handling
- Clean tabular output with detailed summary

## Installation

```bash
# Clone repository
git clone <repository-url>
cd cloudflare-domain-validator

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
# Check single domain
python3 cloudflare_domain_validator.py example.com

# Check multiple domains
python3 cloudflare_domain_validator.py domain1.com domain2.com domain3.com

# Use domains.txt file
python3 cloudflare_domain_validator.py -f domains.txt
```

### Advanced Options
```bash
# Custom timeouts and retries
python3 cloudflare_domain_validator.py -f domains.txt \
  --connect-timeout 3 \
  --read-timeout 5 \
  --retry-attempts 3 \
  --retry-delay 1

# Disable retry logic
python3 cloudflare_domain_validator.py -f domains.txt --no-retry

# Output formats
python3 cloudflare_domain_validator.py -f domains.txt --format table      # Human-readable table (default)
python3 cloudflare_domain_validator.py -f domains.txt --format json      # Full nested JSON
python3 cloudflare_domain_validator.py -f domains.txt --format csv       # Minimal CSV for spreadsheets

# Save output to file
python3 cloudflare_domain_validator.py -f domains.txt --output results.json --format json
python3 cloudflare_domain_validator.py -f domains.txt --output results.csv --format csv

# Parallel processing
python3 cloudflare_domain_validator.py -f domains.txt --parallel-workers 5  # Increase parallel workers
```

### Output Columns
| Column | Description |
|--------|-------------|
| Domain | Domain name being checked |
| CNAME | CNAME record (if any) |
| IPs | Resolved IP addresses |
| Port80 | HTTP port status (open/closed) |
| Port443 | HTTPS port status (open/closed) |
| 80→443 | Redirects from HTTP to HTTPS |
| HTTPS_200 | HTTPS returns 200 OK |
| Page | HTTP status label |
| Cloudflare | Detection result (no/yes-high/yes-medium/yes-low) |

## Cloudflare Detection Methods

### Confidence Levels
- **High (≥80)**: Multiple detection methods match (IP + CNAME + Headers)
- **Medium (60-79)**: Single strong indicator (CNAME pattern or IP range)
- **Low (<60)**: Weak indicators only (headers only)
- **No**: No Cloudflare detected

### Detection Indicators
1. **IP Range**: IP matches Cloudflare's published IPv4 ranges
2. **CNAME Pattern**: CNAME contains `.cloudflare.net` or `.cloudflare.com`
3. **HTTP Headers**: Presence of `CF-Ray`, `Server: cloudflare`, `CF-Cache-Status` headers

## Example Output

```
Domain                       | CNAME                                           | IPs                         | Port80 | Port443 | 80→443 | HTTPS_200 | Page          | Cloudflare
-----------------------------+-------------------------------------------------+-----------------------------+--------+---------+---------+-----------+---------------+-----------
example-cloudflare.com       | example-cloudflare.com.cdn.cloudflare.net      | 104.16.0.0/13              | open   | open    | yes     | yes       | 200 OK        | yes-high
example-non-cf.com           | -                                               | 192.168.1.1                | closed | closed  | no      | no        | -             | no
```

### Cloudflare Summary
After the table, a detailed summary shows:
- Domains grouped by confidence level
- Detection methods used per domain
- Statistics on detection methods

## Use Cases

- **Security Audits**: Identify which domains use Cloudflare protection
- **Infrastructure Mapping**: Map domain accessibility and CDN usage
- **Compliance Checks**: Verify TLS certificates and HTTP redirects
- **One-time Audits**: Check 200-500 domains in single run

## Configuration Defaults

- Connect timeout: 2.0 seconds
- Read timeout: 3.0 seconds
- Retry attempts: 2
- Retry delay: 0.5 seconds
- Parallel workers: 3 domains

## Requirements

- Python 3.6+
- `dnspython` (optional, for enhanced CNAME resolution)
- Network connectivity to target domains

## Notes

- IPv6 detection not yet implemented (focus on IPv4)
- Multiple output formats: table (default), JSON (full nested), CSV (minimal columns)
- Use `--output` flag to save results to file
- Backward compatible with original `cloudflare` boolean field
- Includes detailed error messages for troubleshooting

## License

[MIT License](LICENSE)