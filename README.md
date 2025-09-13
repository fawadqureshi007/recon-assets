ShadowEnum

ShadowEnum is a fast and asynchronous subdomain enumeration tool designed for penetration testers, bug bounty hunters, and security researchers. It combines brute-force, DNS resolution, API integrations, CRT.sh, and Shodan lookups to find live subdomains and gather threat intelligence.

Developed by: Fawad Qureshi

Features

Asynchronous DNS resolution (using Cloudflare 1.1.1.1 / 1.0.0.1)

Brute-force subdomain enumeration using custom wordlists

API integrations for more comprehensive results:

VirusTotal – subdomains & reputation

SecurityTrails – historical & live subdomains

AlienVault OTX – passive DNS & threat intelligence

CRT.sh support for historical subdomains

Shodan lookups for public IPs (open ports, organization, CVEs)

Duplicate filtering by IP for cleaner results

Export results in TXT, JSON, and HTML formats

Fully asynchronous for faster scans

Installation

Clone the repository:
git clone https://github.com/fawadqureshi007/recon-assets.git
cd recon-assets

Install dependencies:
pip install -r requirements.txt

Setup

ShadowEnum requires API keys for VirusTotal, SecurityTrails, AlienVault, and Shodan. On the first run, it automatically creates a .env file in your home directory with placeholders. Edit it with your API keys:
