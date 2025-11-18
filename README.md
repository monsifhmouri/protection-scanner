# Protection Scanner

Advanced website protection scanning tool that automatically crawls and analyzes all types of security protections on websites.

## Features

- **WAF Detection** - Cloudflare, Imperva, Akamai, Sucuri, Fortinet, F5
- **CDN Detection** - Cloudflare, Akamai, Fastly, CloudFront, MaxCDN
- **Security Headers Analysis** - X-Frame-Options, CSP, HSTS, etc.
- **Bot Protection Detection** - reCAPTCHA, hCaptcha, DataDome, Distil
- **Auto Crawling** - Automatically discovers and scans all site pages
- **Detailed Reports** - JSON reports with comprehensive findings
- **Async Performance** - Fast scanning using asynchronous requests

## Installation

```bash
# Clone the repository
git clone https://github.com/monsifhmouri/protection-scanner.git
cd protection-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python protection_scanner.py example.com

# Scan specific number of pages
python protection_scanner.py example.com -p 100

# Set custom timeout
python protection_scanner.py example.com -t 15

# Full scan with all options
python protection_scanner.py example.com -p 100 -t 20
```

## Crawling & Scanning

The tool automatically:
- Discovers all pages on the website
- Analyzes each page for security protections
- Detects WAF, CDN, security headers, and bot protection
- Generates detailed JSON reports
- Scans up to 50 pages by default (configurable with -p)

## Parameters

- `url`: Target website (required)
- `-p, --pages`: Number of pages to scan (default: 50)
- `-t, --timeout`: Request timeout in seconds (default: 10)
