#!/usr/bin/env python3
"""Surface Scan — security recon server (Flask + Python 3)."""

import re
import socket
import time
import concurrent.futures
from urllib.parse import urlparse, urlencode

import requests
import dns.resolver
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="public", static_url_path="")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SurfaceScan/1.0)"}
TIMEOUT = 15  # seconds for HTTP requests

# ── Helpers ───────────────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urlparse(raw).hostname or raw
    raw = re.sub(r"^www\.", "", raw)
    return raw.split("/")[0]


def safe_get(url, **kwargs):
    """GET with sane defaults; returns (response | None, error_str | None)."""
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("headers", HEADERS)
    kwargs.setdefault("allow_redirects", True)
    try:
        r = requests.get(url, **kwargs)
        return r, None
    except Exception as e:
        return None, str(e)


# ── 1. HTTP Security Headers ─────────────────────────────────────────────────

HEADER_CHECKS = [
    {"name": "strict-transport-security",  "label": "Strict-Transport-Security", "severity": "high",
     "desc": "Forces HTTPS. Missing = downgrade/MITM attack risk."},
    {"name": "content-security-policy",    "label": "Content-Security-Policy",   "severity": "high",
     "desc": "Restricts resource origins. Missing = XSS risk."},
    {"name": "x-frame-options",            "label": "X-Frame-Options",           "severity": "medium",
     "desc": "Prevents clickjacking via iframes."},
    {"name": "x-content-type-options",     "label": "X-Content-Type-Options",    "severity": "medium",
     "desc": "Prevents MIME sniffing. Should be 'nosniff'."},
    {"name": "referrer-policy",            "label": "Referrer-Policy",           "severity": "medium",
     "desc": "Controls referrer info sent with requests."},
    {"name": "permissions-policy",         "label": "Permissions-Policy",        "severity": "low",
     "desc": "Controls browser feature access (camera, mic, geo)."},
]


@app.route("/api/headers")
def api_headers():
    domain = clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.head(url, timeout=12, headers=HEADERS, allow_redirects=True)
            h = {k.lower(): v for k, v in resp.headers.items()}

            results = []
            for c in HEADER_CHECKS:
                present = c["name"] in h
                results.append({
                    "header":   c["label"],
                    "present":  present,
                    "value":    h.get(c["name"]),
                    "severity": c["severity"],
                    "desc":     c["desc"],
                })

            missing = [r for r in results if not r["present"]]
            m_high = sum(1 for r in missing if r["severity"] == "high")
            m_med  = sum(1 for r in missing if r["severity"] == "medium")
            if m_high >= 2:       grade = "F"
            elif m_high == 1:     grade = "D"
            elif m_med >= 2:      grade = "C"
            elif m_med == 1:      grade = "B"
            elif not missing:     grade = "A+"
            else:                 grade = "A"

            server_hdr  = h.get("server")
            powered_by  = h.get("x-powered-by")
            return jsonify({
                "success":       True,
                "url":           url,
                "grade":         grade,
                "results":       results,
                "serverHeader":  server_hdr,
                "poweredBy":     powered_by,
                "serverExposed": bool(server_hdr or powered_by),
            })
        except Exception:
            continue

    return jsonify({"success": False, "error": "Could not connect to domain"})


# ── 2. SSL Labs ───────────────────────────────────────────────────────────────

@app.route("/api/ssl")
def api_ssl():
    domain = clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    api = "https://api.ssllabs.com/api/v3/analyze"
    deadline = time.time() + 180

    try:
        # Try cached result first
        r, err = safe_get(f"{api}?host={domain}&all=done&fromCache=on&maxAge=24")
        if err or not r:
            return jsonify({"success": False, "error": err or "SSL Labs unreachable"})
        data = r.json()

        # Start fresh if nothing cached
        if data.get("status") != "READY":
            r, err = safe_get(f"{api}?host={domain}&startNew=on&all=done")
            if err or not r:
                return jsonify({"success": False, "error": err or "SSL Labs unreachable"})
            data = r.json()

        # Poll until done
        while data.get("status") not in ("READY", "ERROR") and time.time() < deadline:
            time.sleep(10)
            r, err = safe_get(f"{api}?host={domain}&all=done")
            if err or not r:
                break
            data = r.json()

        if data.get("status") == "ERROR":
            return jsonify({"success": False, "error": data.get("statusMessage", "SSL Labs scan failed")})
        if data.get("status") != "READY":
            return jsonify({"success": False, "error": "SSL scan timed out — check SSL Labs directly"})

        endpoints = []
        for ep in data.get("endpoints", []):
            d = ep.get("details") or {}
            protocols = []
            for p in d.get("protocols", []):
                protocols.append({
                    "name":       p.get("name"),
                    "version":    p.get("version"),
                    "deprecated": p.get("name") == "TLS" and p.get("version") in ("1.0", "1.1"),
                })
            hsts = None
            if d.get("hstsPolicy"):
                hp = d["hstsPolicy"]
                hsts = {
                    "status":            hp.get("status"),
                    "maxAge":            hp.get("maxAge"),
                    "includeSubDomains": hp.get("includeSubDomains"),
                    "preload":           hp.get("preload"),
                }
            endpoints.append({
                "ipAddress":       ep.get("ipAddress"),
                "grade":           ep.get("grade", "N/A"),
                "hasWarnings":     ep.get("hasWarnings"),
                "protocols":       protocols,
                "hsts":            hsts,
                "certExpiry":      (d.get("cert") or {}).get("notAfter"),
                "certIssuer":      (d.get("cert") or {}).get("issuerLabel"),
                "heartbleed":      d.get("heartbleed", False),
                "poodle":          d.get("poodle", False),
                "vulnerableBeast": d.get("vulnBeast", False),
                "supportsRC4":     d.get("supportsRc4", False),
            })

        order = ["A+", "A", "B", "C", "D", "E", "F", "T", "M", "N/A"]
        top = min((ep["grade"] for ep in endpoints if ep["grade"] in order),
                  key=lambda g: order.index(g), default="N/A")

        return jsonify({"success": True, "host": domain, "grade": top, "endpoints": endpoints})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── 3. DNS Records ────────────────────────────────────────────────────────────

@app.route("/api/dns")
def api_dns():
    domain = clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    findings = []
    spf = dmarc = None
    mx = ns = a = txt = []

    # SPF (TXT on root)
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        txt = ["".join(r.strings.decode() if isinstance(r.strings, bytes) else
                       [s.decode() if isinstance(s, bytes) else s for s in r.strings])
               for r in answers]
        spf_val = next((t for t in txt if t.startswith("v=spf1")), None)
        spf = {"present": bool(spf_val), "value": spf_val}
        if not spf_val:
            findings.append({"severity": "high", "message": "No SPF record — domain can be used to send spoofed email"})
    except Exception:
        spf = {"present": False}
        findings.append({"severity": "high", "message": "No SPF record — domain can be used to send spoofed email"})

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = ["".join(r.strings.decode() if isinstance(r.strings, bytes) else
                                 [s.decode() if isinstance(s, bytes) else s for s in r.strings])
                         for r in answers]
        dmarc_val = next((t for t in dmarc_records if t.startswith("v=DMARC1")), None)
        if dmarc_val:
            pm = re.search(r"p=(\w+)", dmarc_val, re.I)
            policy = pm.group(1).lower() if pm else "none"
            dmarc = {"present": True, "value": dmarc_val, "policy": policy}
            if policy == "none":
                findings.append({"severity": "medium", "message": 'DMARC policy is "none" — monitoring only, no enforcement'})
            elif policy == "quarantine":
                findings.append({"severity": "low", "message": 'DMARC policy is "quarantine" — consider upgrading to "reject"'})
        else:
            dmarc = {"present": False}
            findings.append({"severity": "high", "message": "No DMARC record — no enforcement against spoofed email"})
    except Exception:
        dmarc = {"present": False}
        findings.append({"severity": "high", "message": "No DMARC record — no enforcement against spoofed email"})

    # MX
    try:
        mx = sorted(
            [{"host": str(r.exchange).rstrip("."), "priority": r.preference}
             for r in dns.resolver.resolve(domain, "MX")],
            key=lambda x: x["priority"]
        )
    except Exception:
        mx = []

    # NS
    try:
        ns = [str(r).rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
    except Exception:
        ns = []

    # A
    try:
        a = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except Exception:
        a = []

    findings.append({
        "severity": "info",
        "message": "DKIM requires knowing your email provider's selector — verify manually (e.g. google._domainkey, default._domainkey)"
    })

    m_high = sum(1 for f in findings if f["severity"] == "high")
    m_med  = sum(1 for f in findings if f["severity"] == "medium")
    grade = "F" if m_high >= 2 else "D" if m_high == 1 else "C" if m_med >= 1 else "A"

    return jsonify({"success": True, "domain": domain, "grade": grade,
                    "spf": spf, "dmarc": dmarc, "mx": mx, "ns": ns, "a": a,
                    "txt": txt, "findings": findings})


# ── 4. Port Scan ──────────────────────────────────────────────────────────────

PORTS = [
    (21,    "FTP",        "high",     "Plain-text file transfer — replace with SFTP"),
    (22,    "SSH",        "info",     "Remote access — ensure key-based auth, disable root login"),
    (23,    "Telnet",     "critical", "Unencrypted remote shell — never expose publicly"),
    (25,    "SMTP",       "medium",   "Mail transfer — verify not an open relay"),
    (53,    "DNS",        "info",     "DNS server"),
    (80,    "HTTP",       "info",     "Confirm all traffic redirects to HTTPS"),
    (110,   "POP3",       "medium",   "Plain-text email retrieval"),
    (143,   "IMAP",       "medium",   "Plain-text email access — prefer IMAPS (993)"),
    (443,   "HTTPS",      "info",     "Standard secure web traffic"),
    (445,   "SMB",        "critical", "Windows file sharing — never expose to internet"),
    (993,   "IMAPS",      "info",     "Secure IMAP"),
    (995,   "POP3S",      "info",     "Secure POP3"),
    (3306,  "MySQL",      "critical", "Database exposed to internet — firewall immediately"),
    (3389,  "RDP",        "critical", "Remote Desktop — major ransomware attack vector"),
    (5432,  "PostgreSQL", "critical", "Database exposed to internet — firewall immediately"),
    (5900,  "VNC",        "critical", "Remote desktop — never expose publicly"),
    (6379,  "Redis",      "critical", "Often unauthenticated when exposed — critical risk"),
    (8080,  "HTTP-Alt",   "medium",   "May expose dev/admin interfaces publicly"),
    (8443,  "HTTPS-Alt",  "low",      "Alternate HTTPS port"),
    (27017, "MongoDB",    "critical", "Database exposed to internet — firewall immediately"),
]


def probe_port(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


@app.route("/api/ports")
def api_ports():
    domain = clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return jsonify({"success": False, "error": "Could not resolve IP for domain"})

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe_port, ip, p[0]): p for p in PORTS}
        results = []
        for fut, p in futures.items():
            port, name, risk, note = p
            results.append({"port": port, "name": name, "risk": risk, "note": note, "open": fut.result()})

    results.sort(key=lambda x: x["port"])
    open_ports  = [r for r in results if r["open"]]
    crit_count  = sum(1 for p in open_ports if p["risk"] == "critical")
    high_count  = sum(1 for p in open_ports if p["risk"] == "high")
    grade = "F" if crit_count > 0 else "D" if high_count > 0 else \
            "C" if any(p["risk"] == "medium" for p in open_ports) else "A"

    return jsonify({"success": True, "domain": domain, "ip": ip, "grade": grade,
                    "ports": results, "openCount": len(open_ports), "critCount": crit_count})


# ── 5. CMS / Tech Detection ───────────────────────────────────────────────────

CMS_SIGS = [
    ("WordPress",   [r"wp-content/", r"wp-includes/", r"wp-json/"]),
    ("Drupal",      [r"/sites/default/", r"Drupal\.settings"]),
    ("Joomla",      [r"/components/com_", r"Joomla!"]),
    ("Shopify",     [r"cdn\.shopify\.com", r"myshopify\.com"]),
    ("Wix",         [r"wixstatic\.com", r"wix\.com/static"]),
    ("Squarespace", [r"squarespace\.com", r"sqspcdn\.com"]),
    ("Webflow",     [r"webflow\.com", r"\.webflow\.io"]),
    ("Ghost",       [r"ghost/api/", r"content/themes/"]),
    ("Next.js",     [r"__NEXT_DATA__", r"/_next/static/"]),
    ("Gatsby",      [r"gatsby-chunk-mapping", r"/page-data/"]),
    ("React",       [r"react-dom\.production", r"__reactFiber"]),
    ("Vue.js",      [r"vue\.runtime\.min", r'data-v-[a-f0-9]+=']),
    ("Angular",     [r"ng-version=", r"angular\.min\.js"]),
]


@app.route("/api/cms")
def api_cms():
    domain = clean_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
            html = resp.text[:200_000]
            h = {k.lower(): v for k, v in resp.headers.items()}

            detected = [name for name, patterns in CMS_SIGS
                        if any(re.search(p, html, re.I) for p in patterns)]

            gen_m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
            generator = gen_m.group(1) if gen_m else None
            if generator:
                gen_name = re.split(r"[\s/]", generator)[0]
                if not any(gen_name.lower() in d.lower() for d in detected):
                    detected.append(generator)

            server_hdr     = h.get("server")
            powered_by     = h.get("x-powered-by")
            cf_ray         = h.get("cf-ray")
            via_hdr        = h.get("via")
            version_exposed = bool(server_hdr and re.search(r"\d+\.\d+", server_hdr))
            php_m          = re.search(r"PHP/([\d.]+)", powered_by or "", re.I)
            php_version    = php_m.group(1) if php_m else None

            findings = []
            if version_exposed:
                findings.append({"severity": "medium", "message": f'Server version exposed in header: "{server_hdr}"'})
            if powered_by:
                findings.append({"severity": "low",    "message": f'X-Powered-By header reveals stack: "{powered_by}"'})
            if php_version:
                findings.append({"severity": "medium", "message": f"PHP version {php_version} disclosed — check for known CVEs"})
            if cf_ray:
                findings.append({"severity": "info",   "message": "Site is behind Cloudflare CDN/WAF"})

            cdn = "Cloudflare" if cf_ray else (via_hdr or None)

            return jsonify({
                "success":        True,
                "url":            url,
                "detected":       detected,
                "generator":      generator,
                "serverHeader":   server_hdr,
                "poweredBy":      powered_by,
                "versionExposed": version_exposed,
                "phpVersion":     php_version,
                "cdn":            cdn,
                "findings":       findings,
            })
        except Exception:
            continue

    return jsonify({"success": False, "error": "Could not fetch page"})


# ── Static / Root ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("public", "index.html")


if __name__ == "__main__":
    port = 3000
    print(f"\n  Surface Scan  →  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
