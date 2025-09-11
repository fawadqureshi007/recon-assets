# CipherPhantom

CipherPhantom is an **asynchronous subdomain enumeration tool** combining brute-force, API sources, CRT.sh, and Shodan. It outputs live subdomains with IP resolution and threat intelligence information.

---

## Features

* Async DNS resolution using Cloudflare (1.1.1.1, 1.0.0.1)
* Brute-force subdomain enumeration via custom wordlists
* API integrations for enhanced results:

  * **VirusTotal** – Retrieve subdomains and reputation
  * **SecurityTrails** – Historical and live subdomains
  * **AlienVault OTX** – Passive DNS and threat intelligence
* **CRT.sh** support for historical subdomains
* **Shodan** queries for public IPs (ports, OS, vulnerabilities)
* Duplicate filtering by IP
* Export results in TXT and JSON formats

---

## Installation

Clone the repository:

```bash
git clone https://github.com/fawadqureshi007/recon-assets.git
cd recon-assets
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Setup Environment Variables

CipherPhantom requires API keys stored in a `.env` file. On first run, it automatically creates `~/.env` with placeholders. Update it with your API keys:

```env
SHODAN_API_KEY=your_shodan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SECURITYTRAILS_API_KEY=your_securitytrails_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key
```

> **Important:** Never commit your API keys. Add `.env` to `.gitignore`.

---

## Usage

Basic brute-force scan:

```bash
python cipherphantom.py example.com -w wordlist.txt
```

API-based enumeration:

```bash
python cipherphantom.py example.com --api
```

Use CRT.sh:

```bash
python cipherphantom.py example.com --crtsh
```

Query Shodan:

```bash
python cipherphantom.py example.com --shodan
```

Save results:

```bash
python cipherphantom.py example.com -oT results.txt -oJ results.json
```

Combine all features:

```bash
python cipherphantom.py example.com -w wordlist.txt --api --crtsh --shodan -oT live.txt -oJ live.json
```

---

## Optional Flags

* `--dont-filter-ip` : Disable duplicate IP filtering
* `-oT`, `--output-txt` : Save output to TXT file
* `-oJ`, `--output-json` : Save output to JSON file

---

## Contributing

Pull requests, issues, and suggestions are welcome.

---

## License

MIT License – See `LICENSE` file for details.

---
