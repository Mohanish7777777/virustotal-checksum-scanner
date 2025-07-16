# 🛡️ VirusTotal Checksum Scanner

A lightweight Flask web application to **verify file integrity** using **SHA-256 checksum** and detect file threats using the [VirusTotal API](https://www.virustotal.com).

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-green?logo=flask)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 🚀 Features

- ✅ Upload any file via a user-friendly web interface
- 🔐 Computes **SHA-256 checksum**
- 🦠 Queries **VirusTotal API** for threat detection
- 🔎 Displays malicious/suspicious/undetected counts
- 🔗 Direct link to full VirusTotal scan report
- 🧪 Checks integrity without uploading the file itself (only hash is used)

---

## 🧰 Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML5, CSS3
- **Security & Hashing**: `hashlib`, `requests`
- **API Integration**: [VirusTotal Public API v3](https://developers.virustotal.com/)
- **Environment Handling**: `python-dotenv`

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/virustotal-checksum-scanner.git
cd virustotal-checksum-scanner
```
