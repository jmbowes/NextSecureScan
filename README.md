# NextSecureScan - Next.js-CVE-2025-29927 Middleware Vulnerability Scanner

**NextSecureScan** is a comprehensive security scanner specifically designed to identify middleware-related authorization bypass vulnerabilities (CVE-2025-29927) in Next.js applications. This scanner leverages explicit header manipulation techniques, middleware redirect detection, and advanced polyglot bypass methods to provide thorough vulnerability assessments.

## 🛡️ Features

- **Middleware Detection**: Explicitly detects Next.js middleware usage through standard and advanced HTTP header checks (`x-middleware-rewrite`, `x-middleware-set-cookie`).
- **Redirect Analysis**: Clearly identifies middleware-induced redirects (HTTP 307) and examines headers (`x-nextjs-redirect`, `x-nextjs-rewrite`) to assess middleware protection explicitly.
- **Polyglot Header Bypass**: Utilizes a polyglot `X-Middleware-Subrequest` header to efficiently test multiple middleware paths simultaneously.
- **Version-Specific Testing**: Explicitly tests middleware configurations known to different Next.js versions.
- **Locale-based Redirect & Cache Poisoning Checks**: Detects potential cache poisoning and denial-of-service scenarios caused by bypassing locale-based redirects.
- **Clear & Structured Console Output**: Provides color-coded, readable console outputs clearly indicating vulnerability findings and middleware protections.

## 🚩 CVE Reference

- **CVE-2025-29927**: Authorization bypass vulnerability in Next.js middleware

## 📖 Source Articles and References

- [Assetnote Comprehensive Analysis](https://slcyber.io/assetnote-security-research-center/doing-the-due-diligence-analysing-the-next-js-middleware-bypass-cve-2025-29927/)
- [Understanding CVE-2025-29927](https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/)
- [Building a More Reliable Check - Middleware Polyglot Method](https://github.com/strobes-security/nextjs-vulnerable-app)

## 🛠️ Installation

### Prerequisites

- Python 3.x
- Required Python libraries:

```bash
pip install requests beautifulsoup4 urllib3 colorama
```

## 🚀 Usage

### Running the Scanner

Execute the scanner script and provide the URL of the Next.js application:

```bash
python nextjs_scanner.py
```

Then input the target URL when prompted:

```
Enter target URL (with or without https://): your-app-url.com
```

### Example Output

The scanner will explicitly report findings:

```bash
--------------------------------------------------------------------------------
[SCANNING] https://your-app-url.com
[INFO] Middleware redirect detected at https://your-app-url.com. Headers: ['x-nextjs-redirect']
[VULNERABLE] https://your-app-url.com middleware bypassed successfully using middleware.
--------------------------------------------------------------------------------
```

- **Blue:** Currently scanning URL
- **Yellow:** Informational messages (middleware headers detected)
- **Green:** Safe results (middleware protection active)
- **Red:** Vulnerabilities explicitly identified
- **Magenta:** Potential cache poisoning or locale-based redirect issues

## 🔍 Verification and False Positives

Scanner results should be manually verified using tools like **Burp Suite** or browser extensions capable of HTTP header manipulation.

- Confirm baseline middleware behavior explicitly.
- Attempt exploit headers (`X-Middleware-Subrequest`) explicitly to verify bypass potential.

## ⚙️ Contribute and Customize

Feel free to modify, enhance, correct, or hack the script to better suit your needs or contribute improvements back to the community. 
Contributions are always welcome!

## ⚖️ License

This Python script is provided "as-is" without any warranties or
guarantees, express or implied. The author is not responsible for any
damage, loss of data, or other issues that may result from using this
script. Users are encouraged to review and test the code thoroughly
before using it in any critical or production environment. By using this
script, you acknowledge and agree that you are doing so at your own risk
and that the author bears no liability for any consequences arising from
its use or misuse.
