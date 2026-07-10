# ⚡ VulnScanner — XSS & SQL Injection Scanner

> A beautiful, dark-themed web security tool that crawls HTML forms and tests for XSS and SQL Injection vulnerabilities using cURL, DOM parsing, and payload injection.

---

## ⚠️ Disclaimer

**This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY.**  
Only scan web applications you **own** or have **explicit written permission** to test.  
Unauthorized scanning may violate laws including the CFAA and GDPR.

---

## 🚀 Quick Start

### Requirements
- PHP 8.0+ with extensions: `curl`, `dom`, `libxml`
- A local web server: **XAMPP**, **WAMP**, **Laragon**, or PHP's built-in server

### Setup

1. **Place the folder** in your web server's root:
   - XAMPP → `C:\xampp\htdocs\xss-sqli-scanner\`
   - WAMP  → `C:\wamp64\www\xss-sqli-scanner\`

2. **Start your server** and open:
   ```
   http://localhost/xss-sqli-scanner/
   ```

3. **Test it on the demo page** (intentionally vulnerable):
   ```
   http://localhost/xss-sqli-scanner/demo-target.php
   ```
   Enter this URL in the scanner and run a scan!

---

## 📁 Project Structure

```
xss-sqli-scanner/
├── index.html        ← Frontend UI (scanner interface)
├── style.css         ← Dark cyberpunk styling
├── app.js            ← Frontend JavaScript logic
├── scanner.php       ← Core PHP scanning engine
├── payloads.php      ← XSS & SQLi payload library
├── demo-target.php   ← Intentionally vulnerable test page
└── README.md         ← This file
```

---

## 🔬 How It Works

### 1. cURL Fetch
The PHP backend uses `curl_exec()` to download the HTML of the target page, mimicking a real browser with proper headers. Follows redirects and handles HTTPS.

### 2. DOM Parsing
Uses PHP's `DOMDocument` to parse HTML and extract **all `<form>` elements**, including:
- Form `action` URL (resolved to absolute)
- Form `method` (GET/POST)
- All `<input>`, `<textarea>`, and `<select>` fields with names and types

### 3. XSS Payload Injection
For each text-like field in each form:
- Injects known XSS payloads (`<script>alert(1)</script>`, `<img src=x onerror=...>`, etc.)
- Submits the form via cURL
- Checks if the **payload is reflected verbatim** in the response (without HTML encoding)
- Verbatim reflection = vulnerability confirmed

### 4. SQLi Payload Injection
For each field:
- Injects SQL-breaking payloads (`'`, `' OR 1=1--`, `UNION SELECT`, etc.)
- Submits the form via cURL
- Scans response for **database error signatures** (MySQL, PostgreSQL, Oracle, MSSQL, SQLite, PDO)
- Error pattern match = vulnerability detected

### 5. Report Generation
Results are compiled into a structured JSON object, rendered in the UI with:
- Severity summary cards
- Per-finding accordions with payload, evidence, and response snippets
- Exportable JSON and HTML reports

---

## 🎚️ Payload Intensity Levels

| Level  | XSS Payloads | SQLi Payloads | Use Case              |
|--------|-------------|---------------|----------------------|
| Low    | 5           | 5             | Quick smoke test     |
| Medium | 15          | 15            | Standard assessment  |
| High   | 25          | 25            | Thorough testing     |

---

## 🛡️ Security Concepts Learned

### XSS — Output Encoding
**Vulnerable code:**
```php
echo "Hello, " . $_GET['name'];  // Direct output — dangerous!
```
**Secure code:**
```php
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

### SQLi — Prepared Statements
**Vulnerable code:**
```php
$query = "SELECT * FROM users WHERE id = " . $_POST['id'];  // Dangerous!
```
**Secure code:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([':id' => $_POST['id']]);
```

### Content Security Policy (HTTP Header)
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

## 🔐 SSRF Protection Built In
The scanner blocks scanning of:
- `localhost` / `127.0.0.1`
- Private IP ranges (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`)
- Reserved IP ranges

---

## 📤 Export Options
- **JSON** — Machine-readable full scan report
- **HTML** — Standalone formatted security report

---

## 📚 Topics Covered
- **cURL** — HTTP client for page fetching and form submission
- **DOM Parsing** — PHP DOMDocument for HTML form extraction
- **Payload Injection** — Systematic security testing technique
- **XSS** — Reflected Cross-Site Scripting detection
- **SQLi** — Error-based SQL Injection detection
- **SSRF Prevention** — Blocking internal network scanning
- **Output Encoding** — `htmlspecialchars()` for XSS defense
- **Prepared Statements** — PDO parameterization for SQLi defense
