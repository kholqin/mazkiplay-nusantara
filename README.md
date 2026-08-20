# 🇮🇩 Mazkiplay Nusantara 🦅

## Web Security Assessment Toolkit

**Mazkiplay Nusantara** adalah toolkit **Web Security Assessment** berbasis Python dengan arsitektur modular yang dirancang untuk membantu melakukan pemeriksaan keamanan web secara terstruktur.

Project ini dikembangkan dengan pendekatan:

- Modular security checks
- Evidence-based findings
- Deterministic analysis
- Scope-aware assessment
- JSON reporting
- Automated testing
- Defensive security assessment

> ⚠️ **AUTHORIZED TESTING ONLY**
>
> Gunakan Mazkiplay Nusantara hanya terhadap sistem yang kamu miliki atau sistem yang secara eksplisit memberikan izin untuk dilakukan security assessment.
>
> Jangan melakukan pengujian terhadap sistem pihak lain tanpa authorization.

---

# 🦅 Project Overview

Mazkiplay Nusantara menggabungkan beberapa layer pemeriksaan keamanan dalam satu toolkit.

Arsitektur project saat ini terdiri dari dua bagian utama:

```text
app/
├── scanner.py
├── cli.py
└── sentinel/

🚀 Current Features
🛡️ HTTP Security Headers
Menganalisis konfigurasi security header pada HTTP response.
Pemeriksaan dapat mencakup:

Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy

Tujuannya adalah memberikan indikasi konfigurasi security header yang kurang optimal.


Cookie Security Analysis
Melakukan pemeriksaan terhadap atribut keamanan cookie.
Contoh atribut:
Secure
HttpOnly
SameSite
Project juga memiliki analisis terhadap jenis cookie tertentu seperti:
Session cookies
Authentication cookies
CSRF-related cookies

Finding tidak otomatis berarti cookie tersebut dapat dieksploitasi.
Tool memberikan evidence berdasarkan observasi HTTP.
🌐 CORS Analysis
Menganalisis konfigurasi:
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
Access-Control-Allow-Methods
Access-Control-Allow-Headers
Tujuannya untuk mengidentifikasi konfigurasi Cross-Origin Resource Sharing yang berpotensi tidak aman

🛡️ Content Security Policy
Menganalisis directive CSP seperti:
default-src
script-src
style-src
img-src
connect-src
frame-src
object-src
base-uri
form-action
Analysis digunakan untuk memberikan informasi mengenai kualitas konfigurasi Content Security Policy.

🔎 Information Disclosure
Memeriksa informasi teknis yang mungkin diberikan oleh server.
Contoh:
Server
X-Powered-By
Technology fingerprints
Response metadata
Information disclosure tidak otomatis berarti vulnerability kritikal.

Finding harus dianalisis berdasarkan konteks target.

🔀 Redirect Analysis
Menganalisis HTTP redirect chain.
Status code yang dapat diamati:
301
302
307
308
Tool dapat membantu mengidentifikasi:
Redirect chain
HTTP → HTTPS behavior
Destination URL
Redirect configuration
Potentially unusual redirect behavior

🕷️ URL Discovery
Mazkiplay Nusantara memiliki discovery engine untuk menemukan URL yang masih berada dalam scope assessment.
Komponen discovery:
Crawler
robots.txt
sitemap.xml
Crawler menggunakan batasan seperti:
Maximum pages
Request delay
Same-origin restrictions
URL normalization

Hal ini membantu mencegah crawling tanpa batas.

🤖 robots.txt Analysis
Menganalisis:
/robots.txt
Informasi yang dapat ditemukan antara lain:
User-agent
Allow
Disallow
Sitemap
Robots.txt bukan mekanisme access control.

Informasi dari robots.txt harus dianggap sebagai discovery data.

🗺️ sitemap.xml Analysis
Menganalisis sitemap untuk menemukan URL yang dipublikasikan oleh aplikasi.
Contoh:
/sitemap.xml
Discovery dibatasi menggunakan konfigurasi maximum sitemap URLs.

🔐 TLS / HTTPS Analysis
Mazkiplay Nusantara sekarang memiliki TLS inspection.
Pemeriksaan dapat mencakup:
TLS version
Cipher
Certificate subject
Certificate issuer
Certificate SAN
Certificate validity
Hostname match
Certificate expiration
Contoh finding:

TLS Connection Failed
TLS Certificate Hostname Mismatch
Expired TLS Certificate
TLS Certificate Expiring Soon
TLS Certificate Information
TLS findings dibuat berdasarkan observation dan evidence.
Tool tidak mengklaim exploitability hanya berdasarkan konfigurasi TLS.

🌐 DNS Analysis
Sentinel engine memiliki komponen DNS untuk membantu melakukan analysis terhadap informasi DNS yang relevan dengan assessment.
Komponen:
app/sentinel/dns.py

🔍 Subdomain Analysis
Sentinel menyediakan komponen untuk discovery dan analysis subdomain dalam scope yang sesuai.
Komponen:
app/sentinel/subdomains.py
Penggunaan harus tetap mengikuti scope dan authorization target.

🧬 Technology Fingerprinting
Sentinel memiliki fingerprinting engine untuk membantu mengidentifikasi teknologi yang terlihat dari target.
Komponen:
app/sentinel/fingerprint.py
Fingerprinting dapat membantu memahami attack surface dari sisi defensive assessment.

📦 Asset Discovery
Sentinel memiliki komponen asset discovery.
Komponen:
app/sentinel/assets.py
Asset discovery digunakan untuk mengumpulkan informasi mengenai resource yang terlihat selama assessment.

🧾 Evidence Collection
Mazkiplay Nusantara menggunakan pendekatan evidence-based findings.
Setiap finding dapat memiliki informasi seperti:
Finding ID
Title
Severity
Confidence
Category
Description
Evidence
Recommendation
URL
CWE
Metadata
Contoh konsep finding:

Finding
├── ID
├── Title
├── Severity
├── Confidence
├── Category
├── Description
├── Evidence
├── Recommendation
├── URL
├── CWE
└── Metadata

🧠 Sentinel Engine
Sentinel merupakan bagian analysis engine yang lebih terstruktur dalam project.
Struktur utama:

app/sentinel/
├── __init__.py
├── analysis.py
├── archives.py
├── assets.py
├── behavior.py
├── cookies.py
├── correlation.py
├── dns.py
├── evidence.py
├── exposure.py
├── fingerprint.py
├── http.py
├── models.py
├── orchestrator.py
├── ports.py
├── scope.py
├── scoring.py
├── subdomains.py
└── tls.py

🧩 Sentinel Components
analysis.py
Core analysis logic untuk mengubah HTTP/security observations menjadi findings.
models.py
Berisi model data yang digunakan oleh Sentinel.
Model digunakan untuk menjaga struktur data assessment tetap konsisten.

evidence.py
Menyediakan struktur evidence dan metadata security findings.
http.py
Menyediakan HTTP observation dan data yang digunakan oleh analysis engine.

orchestrator.py
Mengatur proses assessment dan koordinasi beberapa komponen Sentinel.
scope.py
Membantu menjaga assessment tetap berada dalam scope yang ditentukan.
scoring.py
Disiapkan untuk struktur scoring/security assessment.

fingerprint.py
Technology fingerprinting.
assets.py
Asset discovery.
cookies.py
Cookie observation dan analysis.
tls.py
TLS observation dan analysis.

dns.py
DNS-related analysis.
subdomains.py
Subdomain discovery/analysis.
exposure.py
Exposure-related analysis.
correlation.py
Correlation antara beberapa observation/finding.

behavior.py
Behavior-related analysis.
archives.py
Archive-related discovery/analysis.
🧰 Legacy / Modular Security Checks
Directory:
modules/
Berisi security checker yang dapat digunakan secara modular.
Struktur utama:

modules/
├── cookies.py
├── cors.py
├── crawler.py
├── csp.py
├── disclosure.py
├── headers.py
├── redirects.py
├── robots.py
├── sitemap.py
└── tls.py

Setiap module mempunyai tanggung jawab tertentu sehingga pengembangan dan testing dapat dilakukan secara terpisah.

🖥️ CLI
CLI utama berada di:
app/cli.py
CLI menyediakan interface untuk menjalankan assessment dan module individual.
Jalankan bantuan:
python -m app.cli --help

📋 Menu
Interactive CLI menyediakan menu assessment dan security modules.
Beberapa module yang tersedia:
HTTP Security Headers
Cookie Security
CORS
Content Security Policy
Information Disclosure
Redirect Analysis
URL Discovery
robots.txt
sitemap.xml
TLS Inspection
Reports
Configuration
About
Menu dapat berubah mengikuti versi project terbaru.

⚙️ Configuration
Configuration engine digunakan untuk mengatur parameter assessment seperti:
Timeout
Request delay
Maximum pages
Maximum sitemap URLs
Output directory
Konfigurasi digunakan oleh scanner dan module agar behavior assessment tetap konsisten.

📊 Reporting
Hasil assessment dapat disimpan dalam format JSON.
Contoh:
reports/
└── scan-example_com-20260818-xxxxxx.json
Format JSON dapat digunakan untuk:
Dashboard
Automation
Data processing
Security reports
Historical analysis

🧪 Testing
Project memiliki automated test suite.
Test mencakup beberapa bagian utama:

CLI
Configuration
Cookies
CORS
Crawler
CSP
Disclosure
Headers
Redirects
Reporting
Robots
Scanner
Sitemap
TLS
Sentinel Analysis
Sentinel Assets
Sentinel Cookies
Sentinel Evidence
Sentinel Fingerprinting
Sentinel HTTP
Sentinel Integration
Sentinel Orchestrator
Sentinel Subdomains
Sentinel TLS

Jalankan seluruh test:
pytest
Atau:
python -m pytest

🔬 Testing Sentinel
Untuk menjalankan test Sentinel:
pytest tests/test_sentinel_*.py
Untuk menjalankan test tertentu:
pytest tests/test_sentinel_analysis.py

🧪 Test Coverage
Test suite digunakan untuk membantu menjaga:
Regression safety
Module correctness
Data model consistency
Finding generation
HTTP behavior
TLS analysis
Integration behavior
Setiap perubahan besar sebaiknya diikuti dengan test.

🛠️ Tools
Project memiliki utility script:
tools/all.sh
Script tersebut dapat digunakan sebagai bagian dari workflow development/testing project.
Sebelum menjalankan script apa pun, periksa isinya:
cat tools/all.sh

📁 Current Project Structure
Mazkiplay-Nusantara/
│
├── app/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner.py
│   │
│   └── sentinel/
│       ├── __init__.py
│       ├── analysis.py
│       ├── archives.py
│       ├── assets.py
│       ├── behavior.py
│       ├── cookies.py
│       ├── correlation.py
│       ├── dns.py
│       ├── evidence.py
│       ├── exposure.py
│       ├── fingerprint.py
│       ├── http.py
│       ├── models.py
│       ├── orchestrator.py
│       ├── ports.py
│       ├── scope.py
│       ├── scoring.py
│       ├── subdomains.py
│       └── tls.py
│
├── modules/
│   ├── cookies.py
│   ├── cors.py
│   ├── crawler.py
│   ├── csp.py
│   ├── disclosure.py
│   ├── headers.py
│   ├── redirects.py
│   ├── robots.py
│   ├── sitemap.py
│   └── tls.py
│
├── tests/
│   ├── test_cli.py
│   ├── test_config.py
│   ├── test_cookies.py
│   ├── test_cors.py
│   ├── test_crawler.py
│   ├── test_csp.py
│   ├── test_disclosure.py
│   ├── test_headers.py
│   ├── test_redirects.py
│   ├── test_reporting.py
│   ├── test_robots.py
│   ├── test_scanner.py
│   ├── test_sentinel_analysis.py
│   ├── test_sentinel_assets.py
│   ├── test_sentinel_cookies.py
│   ├── test_sentinel_evidence.py
│   ├── test_sentinel_fingerprint.py
│   ├── test_sentinel_http.py
│   ├── test_sentinel_integration.py
│   ├── test_sentinel_orchestrator.py
│   ├── test_sentinel_subdomains.py
│   ├── test_sentinel_tls.py
│   ├── test_sitemap.py
│   └── test_tls.py
│
├── tools/
│   └── all.sh
│
├── reports/
│
├── pytest.ini
├── requirements.txt
└── README.md

💻 Installation
Linux / Kali / Debian
git clone https://github.com/kholqin/mazkiplay-nusantara.git
cd mazkiplay-nusantara

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt


📱 Termux
Install dependencies:
pkg update
pkg install git python
Clone repository:
git clone https://github.com/kholqin/mazkiplay-nusantara.git
cd mazkiplay-nusantara
Buat virtual environment:
python -m venv .venv
source .venv/bin/activate

Install requirements:
pip install -r requirements.txt
Jalankan:
python -m app.cli --help
🐍 Python Version
Recommended:
Python 3.10+
Check:

python3 --version
⚡ Quick Start
Check CLI:
python -m app.cli --help
Check version:
python -m app.cli version
Check configuration:
python -m app.cli info
Run authorized assessment:

python -m app.cli scan https://example.com
Save results:
python -m app.cli scan https://example.com --output reports

🎯 Target Scope
Sebelum melakukan assessment:
Pastikan target memang berada dalam scope.
Pastikan kamu memiliki authorization.
Gunakan rate limit yang wajar.
Hindari destructive testing.
Jangan mengakses data pribadi yang tidak diperlukan.
Jangan mencoba mengambil alih akun.
Jangan melakukan denial-of-service.
Simpan evidence secara aman.

🔐 Responsible Security Research
Mazkiplay Nusantara dapat digunakan untuk:
Security assessment
Authorized penetration testing
Bug bounty reconnaissance
Web application auditing
Security configuration review
Defensive research
Security engineering
Regression testing
Tool ini bukan pengganti manual security review.

Hasil scanner harus diverifikasi sebelum dianggap sebagai vulnerability.
⚠️ Important
Severity seperti:
INFO
LOW
MEDIUM
HIGH
CRITICAL
harus dipahami berdasarkan evidence dan konteks.
Sebuah finding hasil automated scanner tidak selalu berarti exploitable vulnerability.

Selalu lakukan:
Observation
    ↓
Evidence
    ↓
Validation
    ↓
Impact Analysis
    ↓
Final Finding

📝 Development
Clone repository:
git clone https://github.com/kholqin/mazkiplay-nusantara.git



