# 🇮🇩 Mazkiplay Nusantara 🦅

### Web Security Assessment Toolkit

Mazkiplay Nusantara adalah toolkit berbasis Python untuk melakukan **web security assessment secara terstruktur** terhadap target yang memang diizinkan untuk diuji.

Project ini menggunakan arsitektur modular sehingga setiap security checker dapat dikembangkan dan diuji secara terpisah.

> ⚠️ **Authorized Testing Only**
>
> Gunakan tool ini hanya pada website, server, aplikasi, atau environment yang kamu miliki atau yang secara eksplisit memberikan izin pengujian.

---

## 🦅 Features

### HTTP Security Headers

Memeriksa konfigurasi security headers seperti:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

---

### 🍪 Cookie Security

Menganalisis atribut keamanan cookie seperti:

- Secure
- HttpOnly
- SameSite

---

### 🌐 CORS Analysis

Memeriksa konfigurasi Cross-Origin Resource Sharing.

Contoh header yang dianalisis:

```text
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
Access-Control-Allow-Methods
```

---

### 🛡️ Content Security Policy

Menganalisis Content-Security-Policy dan directive terkait.

Contoh:

```text
default-src
script-src
style-src
img-src
connect-src
frame-src
```

---

### 🔎 Information Disclosure

Mendeteksi informasi teknis yang diberikan oleh HTTP response, misalnya:

```text
Server
X-Powered-By
```

Temuan seperti ini merupakan indikasi informasi yang terekspos dan tidak otomatis berarti vulnerability.

---

### 🔀 Redirect Analysis

Menganalisis HTTP redirect:

```text
301
302
307
308
```

Tool membantu melihat redirect chain dan konfigurasi HTTPS.

---

### 🕷️ URL Discovery

Project memiliki modul discovery untuk menemukan URL same-origin.

Komponen discovery meliputi:

```text
Crawler
robots.txt
sitemap.xml
```

Discovery dibatasi agar tidak melakukan crawling tanpa batas.

---

### 🔐 TLS Analysis

Modul TLS dirancang untuk membantu memeriksa konfigurasi HTTPS dan sertifikat.

---

### 📊 JSON Reporting

Hasil assessment dapat disimpan dalam format JSON:

```text
reports/
└── scan-example_com-20260818-xxxxxx.json
```

Format JSON membuat hasil scan mudah diproses oleh dashboard atau aplikasi lain.

---

## 🧰 Requirements

Minimal:

- Python 3.10+
- Git
- pip

Disarankan menggunakan virtual environment.

---

# 🚀 Installation

Clone repository:

```bash
git clone https://github.com/USERNAME/Mazkiplay-Nusantara.git
```

Masuk ke directory:

```bash
cd Mazkiplay-Nusantara
```

Buat virtual environment:

```bash
python3 -m venv .venv
```

Aktifkan:

### Linux / Kali / Debian / Termux

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ⚡ Quick Start

Tampilkan bantuan:

```bash
python -m app.cli --help
```

Tampilkan versi:

```bash
python -m app.cli version
```

Tampilkan konfigurasi:

```bash
python -m app.cli info
```

Jalankan assessment:

```bash
python -m app.cli scan https://example.com
```

Gunakan output directory sendiri:

```bash
python -m app.cli scan https://example.com --output reports
```

> Ganti `example.com` dengan target yang memang kamu punya izin untuk menguji.

---

# 📄 Output

Setelah scan selesai, terminal akan menampilkan tabel findings.

Contoh:

```text
Security Findings

┌──────────┬──────────────────────┬────────────────────────┬─────────────┐
│ Severity │ ID                   │ Title                  │ Category    │
├──────────┼──────────────────────┼────────────────────────┼─────────────┤
│ MEDIUM   │ missing-csp          │ Missing CSP            │ headers     │
│ LOW      │ cookie-secure        │ Cookie missing Secure  │ cookies     │
│ INFO     │ server-disclosure    │ Server Information     │ disclosure  │
└──────────┴──────────────────────┴────────────────────────┴─────────────┘
```

Kemudian report JSON disimpan ke:

```text
reports/
```

---

# ⚙️ Configuration

Mazkiplay Nusantara mendukung environment variables.

Contoh:

```bash
export MNP_TIMEOUT=15
export MNP_MAX_PAGES=50
export MNP_CONCURRENCY=3
export MNP_REQUEST_DELAY=0.5
export MNP_VERIFY_TLS=true
```

Kemudian periksa konfigurasi:

```bash
python -m app.cli info
```

Contoh konfigurasi:

```text
Timeout             15s
Max Pages           50
Concurrency         3
Request Delay       0.5s
TLS Verification    True
```

---

# 🏗️ Project Structure

```text
Mazkiplay-Nusantara/
│
├── app/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── reporting.py
│   └── scanner.py
│
├── modules/
│   ├── cookies.py
│   ├── cors.py
│   ├── csp.py
│   ├── crawler.py
│   ├── disclosure.py
│   ├── headers.py
│   ├── redirects.py
│   ├── robots.py
│   ├── sitemap.py
│   └── tls.py
│
├── reports/
│
├── tests/
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

# 🧠 Architecture

```text
                 MAZKIPLAY NUSANTARA
                         │
                         ▼
                    CLI Interface
                         │
                         ▼
                   Scanner Engine
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
       Headers         Cookies         CORS
          │              │              │
          ├──────────────┼──────────────┤
          │              │              │
          ▼              ▼              ▼
         CSP        Disclosure       Redirect
          │
          ▼
       Discovery
          │
     ┌────┼─────┐
     ▼    ▼     ▼
  Crawler robots sitemap
          │
          ▼
       Findings
          │
          ▼
    JSON Reporting
```

---

# 🧪 Testing

Automated tests menggunakan `pytest`.

Jalankan:

```bash
pytest
```

Dengan output lebih detail:

```bash
pytest -v
```

---

# 🖥️ GitHub Pages

Repository ini juga dapat digunakan sebagai basis untuk frontend dashboard.

GitHub Pages cocok untuk:

```text
HTML
CSS
JavaScript
Dashboard
Documentation
Visualization
```

Python scanner **tidak berjalan langsung sebagai backend di GitHub Pages**.

Arsitektur deployment yang direkomendasikan:

```text
GitHub Pages
     │
     ▼
Frontend Dashboard
     │
     │ HTTP API
     ▼
Python Backend
     │
     ▼
Mazkiplay Scanner
     │
     ▼
JSON Findings
```

---

# 🔐 Security & Authorization

Mazkiplay Nusantara dibuat untuk security assessment yang sah.

Gunakan hanya terhadap:

- server milik sendiri;
- localhost/lab;
- staging environment;
- CTF;
- bug bounty scope yang secara eksplisit mengizinkan pengujian;
- sistem yang telah memberikan izin tertulis.

Jangan melakukan scanning terhadap target pihak lain tanpa authorization.

---

# 📌 Current Status

Project masih dalam pengembangan.

### Available

- [x] CLI
- [x] Scanner engine
- [x] HTTP security header checks
- [x] Cookie checks
- [x] CORS checks
- [x] CSP checks
- [x] Information disclosure checks
- [x] Redirect analysis
- [x] Configuration engine
- [x] JSON reporting

### In Development

- [ ] Full crawler integration
- [ ] robots.txt integration
- [ ] sitemap.xml integration
- [ ] TLS analysis integration
- [ ] Automated tests
- [ ] Web dashboard
- [ ] GitHub Actions
- [ ] Docker deployment

---

# 🛣️ Roadmap

## Phase 1 — Core Engine

- Scanner engine
- HTTP analysis
- Security checkers
- JSON reporting

## Phase 2 — Discovery

- robots.txt
- sitemap.xml
- same-origin crawler
- URL inventory

## Phase 3 — Dashboard

- Dark cyber interface
- Garuda branding
- Indonesian red-white visual identity
- Scan history
- Finding dashboard
- JSON report viewer

## Phase 4 — DevOps

- Automated testing
- GitHub Actions
- Docker
- CI validation

---

# 🇮🇩 Mazkiplay Nusantara

Built as a modular security assessment project.

**Scan responsibly. Test with authorization.**

---

## License

Add your chosen license here.

For example:

```text
MIT License
```

or another license appropriate for your project.
