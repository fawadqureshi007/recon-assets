#!/usr/bin/env python3
"""
shadowenum.py
Subdomain Enumeration using Async DNS & APIs
Optionally runs Shodan lookups in parallel for public IPs
"""

import asyncio
import sys
import aiodns
import time
from pathlib import Path
import argparse
import aiohttp
import os
import json
import ipaddress
from dotenv import load_dotenv
# ======BANNER ART====
BANNER_ART = r"""

  _________.__                .___            ___________                     
 /   _____/|  |__ _____     __| _/______  _  _\_   _____/ ____  __ __  _____  
 \_____  \ |  |  \\__  \   / __ |/  _ \ \/ \/ /|    __)_ /    \|  |  \/     \ 
 /        \|   Y  \/ __ \_/ /_/ (  <_> )     / |        \   |  \  |  /  Y Y  \
/_______  /|___|  (____  /\____ |\____/ \/\_/ /_______  /___|  /____/|__|_|  /
        \/      \/     \/      \/                     \/     \/            \/ 

"""
# ===== Colors =====
BLACK   = "\033[30m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"
RESET   = "\033[0m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
# ===== Banner =====
import shutil
import itertools
import random

def print_centered(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns  # fallback 80 cols
    for line in text.splitlines():
        print(color + line.center(width) + RESET)

def print_banner():
    subtitle = ">>> By Team Cyber Hunters <<<"
    contact = "LinkedIn: Black Byt3 | Email: blackbyt3.info@gmail.com"
    team = "Team Members: Mushaib Ahmed | Muhammad Husnain | Muhammad Aeiyan | Fawad Qureshi"
# Fixed colors (no randomness)
    print_centered(BANNER_ART, BRIGHT_GREEN)    # Main banner
    print_centered(subtitle, BRIGHT_YELLOW)     # Subtitle
    print_centered(contact, BRIGHT_MAGENTA)     # Contact info
    print_centered(team, BRIGHT_CYAN)           # Team members
    print()
print_banner()

# ===== NEW: Ensure .env exists =====
ENV_PATH = Path.home() / ".env"
if not ENV_PATH.exists():
    with open(ENV_PATH, "w") as f:
        f.write("VIRUSTOTAL_API_KEY=\n")
        f.write("SECURITYTRAILS_API_KEY=\n")
        f.write("ALIENVAULT_API_KEY=\n")
        f.write("SHODAN_API_KEY=\n")
    print(f"{YELLOW}[+] Created {ENV_PATH} with placeholder API keys{RESET}")

load_dotenv(ENV_PATH)

# ===== Load API Keys =====
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "").strip()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()

# ===== Helper: Public/Private IP check =====
def ip_type(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "Private" if ip_obj.is_private else "Public"
    except ValueError:
        return "Unknown"

# ===== Save results =====
def save_results(domain, live_subdomains, elapsed, shodan_results=None, txt_file=None, json_file=None):
    if txt_file:
        lines = []
        for sub, ips in live_subdomains:
            lines.append(f"[LIVE] {sub}")
            for ip in ips:
                lines.append(f"    IP: {ip} ({ip_type(ip)})")
                if shodan_results and ip in shodan_results:
                    info = shodan_results[ip]
                    lines.append(f"        Shodan: {json.dumps(info, indent=4)}")
                    if info.get("cves"):
                        lines.append(f"        CVEs: {', '.join(info['cves'])}")
            lines.append("")
        lines.append(f"Total unique live subdomains: {len(live_subdomains)}")
        lines.append(f"Scan completed in {elapsed:.2f} seconds")
        Path(txt_file).write_text("\n".join(lines))
        print(f"{YELLOW}[+] TXT results saved to {txt_file}{RESET}")

    if json_file:
        data = {
            "domain": domain,
            "total_live_subdomains": len(live_subdomains),
            "scan_time_seconds": round(elapsed, 2),
            "results": [
                {
                    "subdomain": sub,
                    "ips": [
                        {
                            "ip": ip,
                            "type": ip_type(ip),
                            "shodan": shodan_results.get(ip) if shodan_results else None,
                            "cves": shodan_results.get(ip, {}).get("cves", [])
                        }
                        for ip in ips
                    ]
                }
                for sub, ips in live_subdomains
            ]
        }
        Path(json_file).write_text(json.dumps(data, indent=4))
        print(f"{YELLOW}[+] JSON results saved to {json_file}{RESET}")
# ===== HTML Output =====
def generate_html_report(domain, live_subdomains, elapsed, output_html="report.html", shodan_results=None):
    """
    Generate HTML report with banner, subdomains, and metadata + Shodan info.
    """

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Subdomain Report - {domain}</title>
<style>
 body {{ font-family: monospace; background: #0b0f14; color: #e6eef6; }}
 .banner {{ white-space: pre; text-align: center; color: #7bed9f; }}
 h1 {{ text-align: center; color: #ffd86b; }}
 table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
 th, td {{ padding: 8px; border-bottom: 1px solid #333; vertical-align: top; }}
 th {{ background: #1f2a38; color: #ffd86b; }}
 .meta {{ margin: 10px 0; text-align: center; color: #9fb0cc; }}
 .shodan {{ color: #ff7675; font-size: 0.9em; margin-left: 15px; }}
</style>
</head>
<body>
<div class="banner">{BANNER_ART}</div>
<h1>Black Byt3 Cyber Hunters</h1>
<div class="meta">
Domain: {domain} <br>
Live subdomains: {len(live_subdomains)} <br>
Scan completed in {elapsed:.2f} seconds
</div>
<table>
<tr><th>Subdomain</th><th>IP(s) + Shodan Info</th></tr>
"""

    for sub, ips in live_subdomains:
        ip_rows = []
        for ip in ips:
            ip_info = f"{ip} ({ip_type(ip)})"
            if shodan_results and ip in shodan_results and shodan_results[ip]:
                shodan_info = shodan_results[ip]
                ip_info += "<div class='shodan'>"
                ip_info += f"Org: {shodan_info.get('org', 'N/A')}<br>"
                ip_info += f"ASN: {shodan_info.get('asn', 'N/A')}<br>"
                ip_info += f"Country: {shodan_info.get('country', 'N/A')}<br>"
                ip_info += f"Open Ports: {', '.join(map(str, shodan_info.get('open_ports', [])))}<br>"
                if shodan_info.get("cves"):
                    ip_info += f"<b>CVEs:</b> {', '.join(shodan_info['cves'])}<br>"                
                ip_info += "</div>"
            ip_rows.append(ip_info)
        ip_html = "<br><br>".join(ip_rows)
        html += f"<tr><td>{sub}</td><td>{ip_html}</td></tr>"

    html += """
</table>
</body>
</html>
"""
    Path(output_html).write_text(html, encoding="utf-8")
    print(f"{YELLOW}[+] HTML report saved to {output_html}{RESET}")

# ===== DNS Resolver =====
async def resolve_subdomain(resolver, subdomain):
    try:
        result_a = await resolver.query(subdomain, 'A')
        return subdomain, sorted({r.host for r in result_a})
    except aiodns.error.DNSError:
        return None, None

# ===== Brute-force =====
async def brute_force_subdomains(domain, wordlist_path, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    words = [
        f"{w.strip()}.{domain}"
        for w in Path(wordlist_path).read_text(errors="ignore").splitlines()
        if w.strip() and not w.startswith("#")
    ]
    print(f"{YELLOW}[+] Loaded {len(words)} subdomain candidates{RESET}")

    live_subdomains, seen_items = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub, ips = await resolve_subdomain(resolver, sub)
            if sub and ips and sub not in seen_subdomains:
                seen_subdomains.add(sub)
                key = tuple(ips) if filter_ip else sub
                if key not in seen_items:
                    seen_items.add(key)
                    live_subdomains.append((sub, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub} -> {', '.join(ips)}")

    await asyncio.gather(*(worker(sub) for sub in words))
    return live_subdomains

# ===== API Subdomain Fetch =====
async def fetch_api_subdomains(domain):
    api_results = set()
    async with aiohttp.ClientSession() as session:
        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            try:
                while url:
                    async with session.get(url, headers=headers) as r:
                        if r.status != 200:
                            break
                        data = await r.json()
                        for item in data.get("data", []):
                            api_results.add(item.get("id"))
                        url = data.get("links", {}).get("next")
                print(f"{YELLOW}[+] VirusTotal returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] VT API error: {e}{RESET}")

        # SecurityTrails
        if SECURITYTRAILS_API_KEY:
            try:
                async with session.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"APIKEY": SECURITYTRAILS_API_KEY}
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        for s in data.get("subdomains", []):
                            api_results.add(f"{s}.{domain}")
                        print(f"{YELLOW}[+] SecurityTrails returned {len(data.get('subdomains', []))} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] ST API error: {e}{RESET}")

        # AlienVault OTX
        if ALIENVAULT_API_KEY:
            try:
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                    headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY}
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        for entry in data.get("passive_dns", []):
                            if entry.get("hostname"):
                                api_results.add(entry["hostname"])
                        print(f"{YELLOW}[+] AlienVault returned {len(data.get('passive_dns', []))} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] AlienVault API error: {e}{RESET}")

    return sorted(s for s in api_results if s and s.endswith(domain))

# ===== Resolve API subdomains =====
async def resolve_api_subdomains(subdomains, seen_subdomains, filter_ip=True, concurrency=200):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    live_subdomains, seen = [], set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub_resolved, ips = await resolve_subdomain(resolver, sub)
            if sub_resolved and ips and sub_resolved not in seen_subdomains:
                seen_subdomains.add(sub_resolved)
                key = tuple(ips) if filter_ip else sub_resolved
                if key not in seen:
                    seen.add(key)
                    live_subdomains.append((sub_resolved, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub_resolved} -> {', '.join(ips)}")

    if subdomains:
        await asyncio.gather(*(worker(sub) for sub in subdomains))
    return live_subdomains

# ===== Clean Shodan Data =====
def format_shodan_data(raw_data):
    formatted = {}
    for ip, data in raw_data.items():
        if not data:
            continue

        # Collect open ports
        ports = sorted(data.get("ports", [])) if "ports" in data else []

        # Collect CVEs from all service banners
        cves = set()
        for banner in data.get("data", []):
            vulns = banner.get("vulns", {})
            if vulns:
                cves.update(vulns.keys())

        formatted[ip] = {
            "country": data.get("country_name"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "region": data.get("region_code"),
            "tags": data.get("tags", []),
            "open_ports": ports,
            "cves": sorted(cves) if cves else []
        }
    return formatted

# ===== Shodan Async =====
async def query_shodan_async(ip_list, shodan_api_key):
    if not shodan_api_key:
        print(f"{RED}[!] No Shodan API key provided. Skipping Shodan lookups.{RESET}")
        return {}
        
    async def fetch_shodan(ip):
         try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        print(f"{GREEN}[SHODAN][OK] {ip} -> {len(data.get('ports', []))} open ports{RESET}")
                        return (ip, data)
         except Exception:
           pass
         return None


    tasks = [fetch_shodan(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)
    shodan_data = {ip: data for r in results if r is not None for ip, data in [r]}
    return format_shodan_data(shodan_data)

def print_help():
    print(f"""
{GREEN}usage:{RESET} subenum.py [options] {CYAN}domain{RESET}

{YELLOW}Subdomain Enumeration Tool with Shodan Integration{RESET}

{CYAN}Positional arguments:{RESET}
  {GREEN}domain{RESET}                Target domain (e.g. {YELLOW}example.com{RESET})

{CYAN}Options:{RESET}
  {GREEN}-h{RESET}, {GREEN}--help{RESET}            Show this help message and exit
  {GREEN}-w{RESET}, {GREEN}--wordlist WORDLIST{RESET}
                        Path to subdomain wordlist
  {GREEN}--api{RESET}                 Use API-based enumeration
  {GREEN}--shodan{RESET}              Run Shodan lookups
  {GREEN}-df{RESET}, {GREEN}--dont-filter-ip{RESET}
                        Do not filter results by IP — shows additional
                        virtual-host style subdomains and alias names
  {GREEN}-oT{RESET}, {GREEN}--output-txt FILE{RESET}
                        Save results in TXT format
  {GREEN}-oJ{RESET}, {GREEN}--output-json FILE{RESET}
                        Save results in JSON format
  {GREEN}-oH{RESET}, {GREEN}--output-html FILE{RESET}
                        Save results in HTML format

{CYAN}Examples:{RESET}
  {GREEN}# Brute-force with a wordlist and save JSON{RESET}
    python3 subenum.py {YELLOW}example.com{RESET} -w subs.txt -oJ results.json

  {GREEN}# API enumeration + Shodan enrichment, save HTML{RESET}
    python3 subenum.py {YELLOW}example.com{RESET} --api --shodan -oH report.html

  {GREEN}# Include more hostnames (disable IP filtering){RESET}
    python3 subenum.py {YELLOW}example.com{RESET} -w subs.txt -df
""")

# ===== Main =====
async def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool with Shodan Integration")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--api", action="store_true", help="Use API-based enumeration")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan lookups")
    parser.add_argument("-df", "--dont-filter-ip", action="store_true", help="Do not filter by IP set")
    parser.add_argument("-oT", "--output-txt", help="Save results in TXT format")
    parser.add_argument("-oJ", "--output-json", help="Save results in JSON format")
    parser.add_argument("-oH", "--output-html", help="Save results in HTML format to given file")
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
      print_help()
      sys.exit(0)

    args = parser.parse_args()

    filter_ip = not args.dont_filter_ip
    seen_subdomains = set()
    start_time = time.time()

    print(f"{YELLOW}[+] Starting async subdomain enumeration for {args.domain}{RESET}")
    print(f"{YELLOW}[i] Filtering by IP is {'ON' if filter_ip else 'OFF'}{RESET}")

    tasks = []
    if args.wordlist:
        tasks.append(brute_force_subdomains(args.domain, args.wordlist, seen_subdomains, filter_ip))
    if args.api:
        async def api_task():
            api_subs = await fetch_api_subdomains(args.domain)
            return await resolve_api_subdomains(api_subs, seen_subdomains, filter_ip)
        tasks.append(api_task())

    live_results = await asyncio.gather(*tasks)
    live_subs_total = [item for sublist in live_results for item in sublist]

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Found {len(live_subs_total)} unique live subdomains in {elapsed:.2f} seconds{RESET}")

    shodan_results = {}
    if args.shodan:
        public_ips = sorted({ip for _, ips in live_subs_total for ip in ips if ip_type(ip) == "Public"})
        print(f"{YELLOW}[+] Shodan lookups requested. Querying {len(public_ips)} public IP(s)...{RESET}")
        shodan_results = await query_shodan_async(public_ips, SHODAN_API_KEY)

    if args.output_txt or args.output_json:
        save_results(args.domain, live_subs_total, elapsed, shodan_results, txt_file=args.output_txt, json_file=args.output_json)
    #===HTML FORMAT======
    if args.output_html:
        generate_html_report(args.domain, live_subs_total, elapsed, output_html=args.output_html, shodan_results=shodan_results)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[-] Interrupted by user{RESET}")
