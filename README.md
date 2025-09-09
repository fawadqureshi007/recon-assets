# 🛠 Setup Guide for ReconRoyale & Bug Bounty Lab

### 1️⃣ Clone the repository

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

### 2️⃣ Set up a Python virtual environment

**Linux / Mac:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3️⃣ Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4️⃣ Create `.env` file

**Linux / Mac:**

```bash
cp .env.example .env
```

**Windows:**

```powershell
copy .env.example .env
```

Edit `.env` and add your API keys:

```
SHODAN_API_KEY=your_shodan_key_here
SECURITYTRAILS_API_KEY=your_securitytrails_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

### 5️⃣ Add required wordlists

```bash
mkdir -p wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -O wordlists/subdomains-top1million-20000.txt
```

Optional:

* `common.txt`
* `passwords.txt`

### 6️⃣ Run a sample script

```bash
python scripts/cipherphantom.py --target example.com --wordlist wordlists/subdomains-top1million-20000.txt
```

### 7️⃣ Deactivate virtual environment

```bash
deactivate
```

---






