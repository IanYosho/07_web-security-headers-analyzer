# Web Security Headers & SSL/TLS Telemetry Analyzer

Defensive assessment engine built to inspect **OWASP Recommended HTTP Security Headers** and audit public **SSL/TLS Certificate** parameters in real time.

[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-FF4B4B)](https://streamlit.io/)
[![OWASP](https://img.shields.io/badge/OWASP-Defensive%20Standards-orange)](https://owasp.org/)

> 🚀 **Live Demo:** Access the interactive cloud app at [Deploy Link Pending]

---

## 🛡️ Core Capabilities

- **Defensive HTTP Header Auditing:** Evaluates implementation against OWASP hardening standards:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking defense)
  - `X-Content-Type-Options` (MIME sniffing prevention)
  - `Referrer-Policy` (Leakage protection)
  - `Permissions-Policy` (Browser feature isolation)
- **Security Posture Scoring:** Weighted algorithm yielding an overall posture score and letter grade (A to F), paired with ready-to-use Nginx remediation snippets.
- **SSL/TLS Telemetry Extraction:** Socket-level cryptographic inspection retrieving TLS protocol versions, cipher suites, issuing authorities, and certificate validity windows.

---

## 📸 Telemetry & Inspection Artifacts

### 1. HTTP Security Headers & Posture Score
![Header Audit](Screenshots/01_headers_inspection.png)

### 2. SSL/TLS Certificate Analysis
![TLS Telemetry](Screenshots/02_ssl_tls_telemetry.png)

---

## ⚙️ Local Setup & Execution

To run this tool locally for development or auditing purposes, execute the following commands in your terminal:

```bash
# 1. Clone the repository
git clone [https://github.com/IanYosho/07_web-security-headers-analyzer.git](https://github.com/IanYosho/07_web-security-headers-analyzer.git)
cd 07_web-security-headers-analyzer

# 2. Configure virtual environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install dependencies and run the application
pip install -r requirements.txt
streamlit run app.py

🛠️ Tech Stack
Framework: Streamlit

Language: Python 3

Libraries: requests, cryptography

Core Protocols: HTTP/HTTPS, SSL/TLS Handshake