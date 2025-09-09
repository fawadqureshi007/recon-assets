#!/usr/bin/env python3
"""
CipherPhantom - Custom Subdomain Enumerator
Bruteforce + API sources (Shodan, VirusTotal, SecurityTrails, AlienVault)
Async DNS resolution using Cloudflare (1.1.1.1)
"""

import asyncio
import aiodns
import time
from pathlib import Path
import argparse
import aiohttp
import os
import json
import ipaddress
from dotenv import load_dotenv

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ===== Banner Function =====
def banner():
    print(f"""{RED}
====================================
           Cipher-Enum
      Developed by Fawad Qureshi
====================================
{RESET}""")

# ===== Ensure .env exists =====
ENV_PATH = Path.home() / ".env"
if not ENV_PATH.exists():
    with open(ENV_PATH, "w") as f:
        f.write("SHODAN_API_KEY=\n")
        f.write("VIRUSTOTAL_API_KEY=\n")
        f.write("SECURITYTRAILS_API_KEY=\n")
        f.write("ALIENVAULT_API_KEY=\n")
    print(f"{YELLOW}[+] Created {ENV_PATH} with placeholder API keys{RESET}")

load_dotenv(ENV_PATH)

# ===== Helper: check if IP is public or private =====
def ip_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "Private" if ip_obj.is_private else "Public"
    except ValueError:
        return "Unknown"

# ===== Output saving =====
def save_results(domain, live_subdomains, elapsed, txt_file=None, json_file=None):
    if txt_file:
        with open(txt_file, "w") as f:
            for sub, ips in live_subdomains:
                f.write(f"[LIVE] {sub}\n")
                for ip in ips:
                    f.write(f"    IP: {ip} ({ip_type(ip)})\n")
            f.write(f"\nTotal unique live subdomains: {len(live_subdomains)}\n")
            f.write(f"Scan completed in {elapsed:.2f} seconds\n")
        print(f"{YELLOW}[+] TXT results saved to {txt_file}{RESET}")

    if json_file:
        results_json = {
            "domain": domain,
            "total_live_subdomains": len(live_subdomains),
            "scan_time_seconds": round(elapsed, 2),
            "results": [
                {"subdomain": sub, "ips": [{"ip": ip, "type": ip_type(ip)} for ip in ips]}
                for sub, ips in live_subdomains
            ],
        }
        with open(json_file, "w") as f:
            json.dump(results_json, f, indent=4)
        print(f"{YELLOW}[+] JSON results saved to {json_file}{RESET}")

# ===== DNS Resolver =====
async def resolve_subdomain(resolver, subdomain):
    try:
        result_a = await resolver.query(subdomain, "A")
        ips = sorted({r.host for r in result_a})
        return subdomain, ips
    except aiodns.error.DNSError:
        return None, None

# ===== Brute-force =====
async def brute_force_subdomains(domain, wordlist_path, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ["1.1.1.1", "1.0.0.1"]

    words = []
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(f"{word}.{domain}")

    print(f"{YELLOW}[+] Loaded {len(words)} subdomain candidates{RESET}")

    live_subdomains, seen_items = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub, ips = await resolve_subdomain(resolver, sub)
            if sub and ips:
                if sub in seen_subdomains:
                    return
                seen_subdomains.add(sub)
                key = tuple(ips) if filter_ip else sub
                if key not in seen_items:
                    seen_items.add(key)
                    live_subdomains.append((sub, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub} -> {', '.join(ips)}")

    await asyncio.gather(*[worker(sub) for sub in words])
    return live_subdomains

# ===== API Subdomains =====
async def fetch_api_subdomains(domain):
    api_results = set()
    async with aiohttp.ClientSession() as session:

        # Shodan
        shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
        if shodan_key:
            shodan_url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_key}"
            try:
                async with session.get(shodan_url) as r:
                    if r.status == 200:
                        data = await r.json()
                        for entry in data.get("subdomains", []):
                            api_results.add(f"{entry}.{domain}")
                        print(f"{YELLOW}[+] Shodan returned {len(api_results)} subdomains{RESET}")
                    else:
                        print(f"{RED}[-] Shodan API error {r.status}{RESET}")
            except Exception as e:
                print(f"{RED}[-] Shodan API exception: {e}{RESET}")

        # VirusTotal
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if vt_key:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": vt_key}
            try:
                async with session.get(vt_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        for item in data.get("data", []):
                            api_results.add(item.get("id"))
                        print(f"{YELLOW}[+] VirusTotal returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] VirusTotal error: {e}{RESET}")

        # SecurityTrails
        st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
        if st_key:
            st_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": st_key}
            try:
                async with session.get(st_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        for s in data.get("subdomains", []):
                            api_results.add(f"{s}.{domain}")
                        print(f"{YELLOW}[+] SecurityTrails returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] SecurityTrails error: {e}{RESET}")

        # AlienVault OTX
        av_key = os.getenv("ALIENVAULT_API_KEY", "").strip()
        if av_key:
            av_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            headers = {"X-OTX-API-KEY": av_key}
            try:
                async with session.get(av_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        for entry in data.get("passive_dns", []):
                            hostname = entry.get("hostname")
                            if hostname:
                                api_results.add(hostname)
                        print(f"{YELLOW}[+] AlienVault returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] AlienVault error: {e}{RESET}")

    return sorted(s for s in api_results if s and s.endswith(domain))

# ===== Resolve API subdomains =====
async def resolve_api_subdomains(subdomains, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ["1.1.1.1", "1.0.0.1"]

    live_subdomains, seen_items = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub_resolved, ips = await resolve_subdomain(resolver, sub)
            if sub_resolved and ips:
                if sub_resolved in seen_subdomains:
                    return
                seen_subdomains.add(sub_resolved)
                key = tuple(ips) if filter_ip else sub_resolved
                if key not in seen_items:
                    seen_items.add(key)
                    live_subdomains.append((sub_resolved, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub_resolved} -> {', '.join(ips)}")

    if subdomains:
        await asyncio.gather(*[worker(sub) for sub in subdomains])
    return live_subdomains

# ===== Main =====
async def main():
    banner()  # Show banner at start
    parser = argparse.ArgumentParser(description="CipherPhantom - Async Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--api", action="store_true", help="Use API-based enumeration (Shodan, VT, ST, OTX)")
    parser.add_argument("-df", "--dont-filter-ip", action="store_true", help="Do not filter by IP set (keep duplicates)")
    parser.add_argument("-oT", "--output-txt", help="Save results in TXT format")
    parser.add_argument("-oJ", "--output-json", help="Save results in JSON format")
    args = parser.parse_args()

    filter_ip = not args.dont_filter_ip
    seen_subdomains = set()

    start_time = time.time()
    print(f"{YELLOW}[+] Starting CipherPhantom for {args.domain}{RESET}")
    print(f"{YELLOW}[i] Filtering by IP is {'ON' if filter_ip else 'OFF'}{RESET}")

    live_subs_total = []

    if args.wordlist:
        live_subs = await brute_force_subdomains(args.domain, Path(args.wordlist), seen_subdomains, filter_ip=filter_ip)
        live_subs_total.extend(live_subs)

    if args.api:
        api_subs = await fetch_api_subdomains(args.domain)
        live_api = await resolve_api_subdomains(api_subs, seen_subdomains, filter_ip=filter_ip)
        live_subs_total.extend(live_api)

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Found {len(live_subs_total)} unique live subdomains in {elapsed:.2f} seconds{RESET}")

    if args.output_txt or args.output_json:
        save_results(args.domain, live_subs_total, elapsed, txt_file=args.output_txt, json_file=args.output_json)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[-] Interrupted by user{RESET}")
