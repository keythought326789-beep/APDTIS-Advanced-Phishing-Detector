# APDTIS V5
# ADVANCED PHISHING & THREAT INTELLIGENCE SYSTEM
import os
import re
import socket
import base64
import ipaddress
import requests

from urllib.parse import urlparse, quote


# =====================================================
# APDTIS V5
# ADVANCED PHISHING & THREAT INTELLIGENCE SYSTEM
# =====================================================

VT_API_URL = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VT_API_KEY")
TIMEOUT = 15

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "password",
    "secure", "banking", "update", "confirm",
    "wallet", "free", "prize", "urgent",
    "suspended", "payment"
]

PHISHING_EMAIL_WORDS = [
    "verify your account",
    "account suspended",
    "urgent action",
    "reset your password",
    "confirm your identity",
    "click here",
    "limited time",
    "payment failed"
]

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

LINK_RE = re.compile(
    r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
    re.IGNORECASE
)


# =====================================================
# URL VALIDATION
# =====================================================

def normalize_url(url):

    url = url.strip().rstrip(".,;!?)")

    if not url:
        raise ValueError("Empty URL")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not parsed.hostname:
        raise ValueError("Missing domain name")

    try:
        parsed.port
    except ValueError:
        raise ValueError("Invalid port number")

    hostname = parsed.hostname

    try:
        hostname.encode("idna")
    except UnicodeError:
        raise ValueError("Invalid domain encoding")

    if len(hostname) > 253:
        raise ValueError("Domain name is too long")

    return url


def get_domain(url):

    try:
        return urlparse(normalize_url(url)).hostname
    except (ValueError, TypeError):
        return None


def validate_domain(domain):

    if not domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if len(ascii_domain) > 253:
        return False

    labels = ascii_domain.rstrip(".").split(".")

    if len(labels) < 2:
        return False

    return all(
        1 <= len(label) <= 63
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
            label
        )
        for label in labels
    )


# =====================================================
# DNS INTELLIGENCE
# =====================================================

def dns_check(domain):

    try:
        results = socket.getaddrinfo(domain, None)

        ips = sorted(set(
            item[4][0] for item in results
        ))

        return ips

    except (socket.gaierror, OSError):
        return []


# =====================================================
# LOCAL URL ANALYSIS
# =====================================================

def analyze_url(url):

    url = normalize_url(url)
    parsed = urlparse(url)

    domain = parsed.hostname or ""

    score = 0
    warnings = []

    if not domain:
        return 100, ["Invalid URL or missing domain"]

    if len(url) > 100:
        score += 1
        warnings.append("Unusually long URL")

    if len(url) > 200:
        score += 2
        warnings.append("Very long URL")

    try:
        ipaddress.ip_address(domain)
        score += 3
        warnings.append("IP address used instead of domain")
    except ValueError:
        pass

    if "@" in url:
        score += 3
        warnings.append("@ symbol found in URL")

    if domain.count(".") >= 4:
        score += 2
        warnings.append("Many subdomains detected")

    if parsed.scheme.lower() == "http":
        score += 1
        warnings.append("URL does not use HTTPS")

    for word in SUSPICIOUS_WORDS:

        if word in url.lower():
            score += 1
            warnings.append("Suspicious keyword: " + word)

    if domain.lower().startswith("xn--") or ".xn--" in domain.lower():
        score += 2
        warnings.append("Internationalized domain detected")

    return score, warnings


# =====================================================
# VIRUSTOTAL API
# =====================================================

def vt_request(endpoint):

    if not API_KEY:
        return None, "API key not configured"

    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }

    try:

        response = requests.get(
            VT_API_URL + endpoint,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 200:

            try:
                return response.json(), None
            except ValueError:
                return None, "Invalid JSON response from VirusTotal"

        error_messages = {
            400: "Invalid VirusTotal request",
            401: "Invalid API key",
            403: "API access forbidden",
            404: "No existing report found",
            429: "VirusTotal rate limit reached"
        }

        if response.status_code in error_messages:
            return None, error_messages[response.status_code]

        return None, "HTTP error: " + str(response.status_code)

    except requests.exceptions.Timeout:
        return None, "VirusTotal request timed out"

    except requests.exceptions.RequestException:
        return None, "Network connection problem"


def extract_vt_stats(data):

    attributes = data.get(
        "data", {}
    ).get("attributes", {})

    stats = attributes.get(
        "last_analysis_stats", {}
    )

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


def vt_scan_url(url):

    try:
        url = normalize_url(url)
    except ValueError as error:
        return None, str(error)

    encoded_url = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    data, error = vt_request(
        "/urls/" + encoded_url
    )

    if error:
        return None, error

    return extract_vt_stats(data), None


def vt_scan_domain(domain):

    if not validate_domain(domain):
        return None, "Invalid domain"

    encoded_domain = quote(domain, safe=".-")

    data, error = vt_request(
        "/domains/" + encoded_domain
    )

    if error:
        return None, error

    result = extract_vt_stats(data)

    attributes = data.get(
        "data", {}
    ).get("attributes", {})

    result["reputation"] = attributes.get(
        "reputation", 0
    )

    return result, None


# =====================================================
# RISK CLASSIFICATION
# =====================================================

def classify_risk(score, vt_data=None):

    if vt_data is not None:

        malicious = vt_data.get("malicious", 0)
        suspicious = vt_data.get("suspicious", 0)

        if malicious > 0:
            return "MALICIOUS"

        if suspicious > 0:
            return "HIGH RISK"

    if score >= 6:
        return "HIGH RISK"

    if score >= 3:
        return "MEDIUM RISK"

    if vt_data is None:
        return "INCONCLUSIVE"

    return "LOW RISK"


# =====================================================
# SECURITY REPORT
# =====================================================

def show_report(
    title,
    score,
    warnings,
    vt_data=None,
    vt_error=None
):

    risk = classify_risk(score, vt_data)

    print("\n" + "=" * 55)
    print("                 SECURITY REPORT")
    print("=" * 55)

    print("Target:", title)
    print("Risk Score:", score)
    print("Final Assessment:", risk)

    print("\n--- LOCAL ANALYSIS ---")

    if warnings:

        for warning in dict.fromkeys(warnings):
            print("[!] " + warning)

    else:
        print("[+] No suspicious local indicators detected.")

    print("\n--- VIRUSTOTAL INTELLIGENCE ---")

    if vt_data:

        print("Malicious:", vt_data.get("malicious", "N/A"))
        print("Suspicious:", vt_data.get("suspicious", "N/A"))
        print("Harmless:", vt_data.get("harmless", "N/A"))
        print("Undetected:", vt_data.get("undetected", "N/A"))

        if "reputation" in vt_data:
            print("Domain Reputation:", vt_data["reputation"])

    else:
        print("Intelligence Status: Unavailable")
        print("Reason:", vt_error or "No report available")

    print("\nIMPORTANT:")
    print("No detection does NOT guarantee safety.")
    print("INCONCLUSIVE means insufficient intelligence.")
    print("Do not open suspicious links.")

    print("=" * 55)


# =====================================================
# URL SCANNER
# =====================================================

def scan_url(url):

    try:
        url = normalize_url(url)
    except ValueError as error:
        print("[!] Invalid URL:", error)
        return

    domain = get_domain(url)

    if not validate_domain(domain):
        print("[!] Invalid domain name.")
        return

    print("\n[+] URL detected!")
    print("[+] Starting local analysis...")

    score, warnings = analyze_url(url)

    print("[+] Checking DNS...")

    ips = dns_check(domain)

    if ips:
        print("[+] Domain IP:", ", ".join(ips))
    else:
        score += 2
        warnings.append("Domain DNS lookup failed")

    print("[+] Checking VirusTotal existing report...")

    vt_data, vt_error = vt_scan_url(url)

    if vt_error:
        print("[!] URL intelligence:", vt_error)

    show_report(
        url,
        score,
        warnings,
        vt_data,
        vt_error
    )


# =====================================================
# EMAIL LINK EXTRACTION
# =====================================================

def extract_email_links(data):

    links = LINK_RE.findall(data)

    cleaned = []

    for link in links:

        link = link.rstrip(".,;!?)")

        if link.lower().startswith("www."):
            link = "https://" + link

        try:
            link = normalize_url(link)

            if link not in cleaned:
                cleaned.append(link)

        except ValueError:
            continue

    return cleaned


# =====================================================
# EMAIL SCANNER
# =====================================================

def scan_email(data):

    print("\n[+] Email detected!")

    score = 0
    warnings = []

    emails = EMAIL_RE.findall(data)
    urls = extract_email_links(data)

    vt_data = None
    vt_error = None

    # Sender domain analysis

    if emails:

        email = emails[0]
        domain = email.split("@")[-1].lower()

        print("[+] Sender email:", email)
        print("[+] Checking sender domain...")

        ips = dns_check(domain)

        if not ips:
            score += 2
            warnings.append("Email domain DNS lookup failed")

        vt_data, vt_error = vt_scan_domain(domain)

        if vt_data:

            if vt_data["malicious"] > 0:
                warnings.append(
                    "Sender domain flagged as malicious"
                )

            if vt_data["suspicious"] > 0:
                warnings.append(
                    "Sender domain has suspicious detections"
                )

        else:
            print("[!] Domain intelligence:", vt_error)

    else:

        vt_error = "No sender email address found"

        score += 1
        warnings.append("No sender email address found")

    # Phishing language analysis

    for word in PHISHING_EMAIL_WORDS:

        if word in data.lower():

            score += 2

            warnings.append(
                "Phishing language detected: " + word
            )

    # Email link analysis

    for url in urls:

        print("[+] Email link found:", url)

        try:
            link_score, link_warnings = analyze_url(url)

            score += link_score
            warnings.extend(link_warnings)

        except ValueError:
            warnings.append("Invalid link detected")

    show_report(
        "Email message",
        score,
        warnings,
        vt_data,
        vt_error
    )

    # Individual URL intelligence reports

    for url in urls:

        print("\n[+] Checking email link with VirusTotal...")

        url_data, url_error = vt_scan_url(url)

        show_report(
            url,
            0,
            [],
            url_data,
            url_error
        )


# =====================================================
# INPUT DETECTION
# =====================================================

def looks_like_url(value):

    candidate = value.strip()

    if candidate.lower().startswith(("http://", "https://")):
        return True

    if candidate.lower().startswith("www."):
        return True

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/[^\s]*)?",
            candidate
        )
    )


# =====================================================
# MAIN PROGRAM
# =====================================================

def main():

    print("\n" + "=" * 55)
    print("       APDTIS V5")
    print("       ADVANCED PHISHING & THREAT INTELLIGENCE")
    print("=" * 55)

    if API_KEY:
        print("[+] VirusTotal API key detected.")
    else:
        print("[!] VirusTotal API key not configured.")

    print("\nEnter a URL, email address or email message.")
    print("Type EXIT to close the program.")

    while True:

        try:
            user_input = input("\nINPUT > ").strip()

        except (EOFError, KeyboardInterrupt):
            print("\nScanner closed.")
            break

        if user_input.upper() == "EXIT":
            print("Scanner closed.")
            break

        if not user_input:
            print("Empty input. Try again.")
            continue

        if looks_like_url(user_input):
            scan_url(user_input)

        elif EMAIL_RE.search(user_input) or "@" in user_input:
            scan_email(user_input)

        else:
            print("[!] Input not recognized.")
            print("[+] Enter a valid URL or email message.")

        print("\n[+] Ready for next scan.")


if __name__ == "__main__":
    main()
