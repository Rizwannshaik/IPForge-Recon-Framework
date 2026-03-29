# 🔥 IPForge Recon Framework

## 🚀 Overview

IPForge is an advanced Python-based reconnaissance framework designed for penetration testers and cybersecurity enthusiasts.

It combines multiple networking and recon techniques into a single powerful CLI tool.

---

## ⚡ Features

### 🌐 Address Format Conversion

* Convert between:

  * IP Address
  * URL
  * DWORD
  * Hexadecimal
  * Octal
  * Mixed formats

---

### 🛡️ WAF Detection

* Behavioral detection (even when headers are hidden)
* Identifies blocking patterns (403, 429, 503)
* Detects anomalies in response behavior

---

### 🔥 WAF Bypass Engine

* Auto-detect best bypass payload
* Manual payload testing
* Header manipulation:

  * X-Forwarded-For
  * X-Real-IP
* Response difference analysis

---

### 📂 Endpoint Discovery

* Built-in common endpoints:

  * admin, api, login, dashboard, test, dev, backup
* Custom wordlist support
* Async parallel scanning

---

### 🌍 Subdomain Enumeration

* Default important subdomains:

  * www, admin, api, dev, staging, mail, vpn
* Custom wordlist support

---

### ⚡ Performance

* Fully asynchronous (asyncio + aiohttp)
* Parallel scanning with rate control
* Optimized for speed and stability

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/IPForge-Recon-Framework.git
cd IPForge-Recon-Framework
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python3 IPForge.py
```

---

## 🧠 Example Workflow

1. Enter target (domain/IP)
2. Convert address formats
3. Run web recon + WAF detection
4. Test WAF bypass techniques
5. Perform endpoint discovery
6. Enumerate subdomains

---

## 📸 Sample Output

```
HTTP → 403
Meaning: Blocked → WAF/CDN
WAF: Possible WAF (Behavioral)
```

---

## 🎯 Use Cases

* Penetration Testing
* Bug Bounty Recon
* Network Security Analysis
* Learning Web Security Concepts

---

## ⚠️ Disclaimer

This tool is intended for educational and authorized testing purposes only. Do not use against systems without permission.

---

## 👨‍💻 Author

Developed by a cybersecurity enthusiast focused on recon automation and offensive security tooling.

---
