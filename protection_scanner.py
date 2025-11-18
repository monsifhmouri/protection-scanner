#!/usr/bin/env python3
"""
Advanced Protection Scanner - Professional Website Security Analysis Tool
Comprehensive tool to scan and identify all types of protection mechanisms on websites
"""

import requests
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import time
from datetime import datetime
import colorama
from colorama import Fore, Style
import pyfiglet
from tqdm import tqdm
import argparse
import sys
import os
import ssl
import socket

colorama.init(autoreset=True)

class ProtectionScanner:
    def __init__(self, target_url, max_pages=50, timeout=10):
        self.target_url = self.normalize_url(target_url)
        self.base_domain = urlparse(target_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.found_pages = set()
        self.protection_results = {}
        self.session = None
        
        self.protection_types = {
            'waf': ['cloudflare', 'imperva', 'akamai', 'sucuri', 'fortinet', 'f5'],
            'cdn': ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'maxcdn'],
            'firewall': ['wordfence', 'sitelock', 'bulletproof', 'all-in-one-wp-security'],
            'server': ['nginx', 'apache', 'iis', 'litespeed'],
            'security_headers': ['x-frame-options', 'x-content-type-options', 
                               'x-xss-protection', 'strict-transport-security'],
            'ssl': ['ssl', 'tls', 'https'],
            'bot_protection': ['recaptcha', 'hcaptcha', 'datadome', 'distil']
        }
        
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def print_banner(self):
        banner = pyfiglet.figlet_format("Protection Scanner", font="small")
        print(Fore.CYAN + banner)
        print(Fore.YELLOW + "=" * 60)
        print(Fore.GREEN + "Advanced Protection Scanner - Version 2.0")
        print(Fore.YELLOW + "=" * 60)
        print()
    
    async def create_session(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=10, verify_ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
    
    async def close_session(self):
        if self.session:
            await self.session.close()
    
    def extract_links(self, html_content, base_url):
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            href = tag.get('href') or tag.get('src')
            if href:
                full_url = urljoin(base_url, href)
                if self.base_domain in full_url:
                    links.add(full_url)
        
        return links
    
    async def fetch_page(self, url):
        try:
            async with self.session.get(url, ssl=False) as response:
                content = await response.text()
                headers = dict(response.headers)
                return content, headers, response.status
        except Exception as e:
            return None, None, str(e)
    
    def detect_waf(self, headers, content):
        waf_indicators = {
            'cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'imperva': ['incap_ses', 'visid_incap'],
            'akamai': ['akamai'],
            'sucuri': ['sucuri/cloudproxy'],
            'fortinet': ['fortigate'],
            'f5': ['f5']
        }
        
        detected_wafs = []
        
        for header_name, header_value in headers.items():
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in header_name.lower() or indicator.lower() in str(header_value).lower():
                        if waf not in detected_wafs:
                            detected_wafs.append(waf)
        
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content.lower():
                    if waf not in detected_wafs:
                        detected_wafs.append(waf)
        
        return detected_wafs
    
    def detect_cdn(self, headers, content):
        cdn_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai', 'x-akamai'],
            'fastly': ['fastly', 'x-fastly'],
            'cloudfront': ['cloudfront', 'x-amz-cf'],
            'maxcdn': ['maxcdn', 'netdna']
        }
        
        detected_cdns = []
        
        for header_name, header_value in headers.items():
            for cdn, indicators in cdn_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in header_name.lower() or indicator.lower() in str(header_value).lower():
                        if cdn not in detected_cdns:
                            detected_cdns.append(cdn)
        
        return detected_cdns
    
    def analyze_security_headers(self, headers):
        security_headers = {
            'x-frame-options': headers.get('x-frame-options', 'Not found'),
            'x-content-type-options': headers.get('x-content-type-options', 'Not found'),
            'x-xss-protection': headers.get('x-xss-protection', 'Not found'),
            'strict-transport-security': headers.get('strict-transport-security', 'Not found'),
            'content-security-policy': headers.get('content-security-policy', 'Not found'),
            'referrer-policy': headers.get('referrer-policy', 'Not found')
        }
        return security_headers
    
    def detect_server(self, headers):
        server = headers.get('server', 'Unknown')
        powered_by = headers.get('x-powered-by', 'Unknown')
        return server, powered_by
    
    def detect_ssl_info(self, url):
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_version = ssock.version()
                    
                    return {
                        'ssl_version': ssl_version,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter']
                    }
        except:
            return {'ssl_version': 'Not available', 'issuer': 'Unknown'}
    
    async def crawl_site(self):
        print(Fore.BLUE + f"[+] Starting crawl: {self.target_url}")
        
        queue = [self.target_url]
        self.found_pages.add(self.target_url)
        
        pbar = tqdm(total=self.max_pages, desc="Crawling")
        
        while queue and len(self.found_pages) < self.max_pages:
            current_url = queue.pop(0)
            
            content, headers, status = await self.fetch_page(current_url)
            
            if content and headers:
                await self.analyze_page(current_url, content, headers)
                
                new_links = self.extract_links(content, current_url)
                
                for link in new_links:
                    if link not in self.found_pages and len(self.found_pages) < self.max_pages:
                        self.found_pages.add(link)
                        queue.append(link)
                        pbar.update(1)
            
            pbar.set_description(f"Scanned {len(self.found_pages)} pages")
        
        pbar.close()
    
    async def analyze_page(self, url, content, headers):
        page_results = {}
        
        page_results['waf'] = self.detect_waf(headers, content)
        
        page_results['cdn'] = self.detect_cdn(headers, content)
        
        page_results['security_headers'] = self.analyze_security_headers(headers)
        
        page_results['server'], page_results['powered_by'] = self.detect_server(headers)
        
        if url == self.target_url:
            page_results['ssl_info'] = self.detect_ssl_info(url)
        
        page_results['bot_protection'] = self.detect_bot_protection(content, headers)
        
        self.protection_results[url] = page_results
    
    def detect_bot_protection(self, content, headers):
        bot_protection_indicators = {
            'recaptcha': ['recaptcha', 'g-recaptcha'],
            'hcaptcha': ['hcaptcha'],
            'datadome': ['datadome'],
            'distil': ['distil'],
            'shield': ['shieldsecurity']
        }
        
        detected_protections = []
        
        for protection, indicators in bot_protection_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content.lower():
                    detected_protections.append(protection)
                    break
        
        return detected_protections
    
    def generate_report(self):
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "Protection Scan Report - Final Results")
        print(Fore.CYAN + "=" * 60)
        
        all_wafs = set()
        all_cdns = set()
        all_bot_protections = set()
        servers = set()
        
        for url, results in self.protection_results.items():
            all_wafs.update(results['waf'])
            all_cdns.update(results['cdn'])
            all_bot_protections.update(results['bot_protection'])
            servers.add(results['server'])
        
        print(Fore.GREEN + f"\n[+] Scanned {len(self.protection_results)} pages")
        
        print(Fore.YELLOW + f"\n[+] Detected WAF Systems:")
        for waf in all_wafs:
            print(Fore.WHITE + f"   - {waf}")
        
        print(Fore.YELLOW + f"\n[+] Detected CDN Networks:")
        for cdn in all_cdns:
            print(Fore.WHITE + f"   - {cdn}")
        
        print(Fore.YELLOW + f"\n[+] Bot Protection Systems:")
        for protection in all_bot_protections:
            print(Fore.WHITE + f"   - {protection}")
        
        print(Fore.YELLOW + f"\n[+] Server Types:")
        for server in servers:
            print(Fore.WHITE + f"   - {server}")
        
        if self.target_url in self.protection_results:
            main_results = self.protection_results[self.target_url]
            print(Fore.YELLOW + f"\n[+] Security Headers for Main Page:")
            for header, value in main_results['security_headers'].items():
                status = Fore.GREEN + "✓" if value != "Not found" else Fore.RED + "✗"
                print(Fore.WHITE + f"   {status} {header}: {value}")
        
        self.save_report_to_file()
    
    def save_report_to_file(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"protection_scan_{self.base_domain}_{timestamp}.json"
        
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'target_url': self.target_url,
            'pages_scanned': len(self.protection_results),
            'results': self.protection_results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(Fore.GREEN + f"\n[+] Report saved to: {filename}")

async def main():
    parser = argparse.ArgumentParser(description='Advanced Protection Scanner')
    parser.add_argument('url', help='Target website (example: example.com)')
    parser.add_argument('-p', '--pages', type=int, default=50, 
                       help='Number of pages to scan (default: 50)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    scanner = ProtectionScanner(args.url, args.pages, args.timeout)
    scanner.print_banner()
    
    try:
        await scanner.create_session()
        await scanner.crawl_site()
        scanner.generate_report()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan stopped by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error occurred: {e}")
    finally:
        await scanner.close_session()

if __name__ == "__main__":
    asyncio.run(main())