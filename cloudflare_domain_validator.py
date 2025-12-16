#!/usr/bin/env python3
"""
cloudflare_domain_validator.py

Usage:
  python3 cloudflare_domain_validator.py example.com [other.com ...]
  python3 cloudflare_domain_validator.py -f domains.txt

Checks DNS resolution and whether ports 80 and 443 are reachable,
returns HTTP status (if any) and basic TLS cert info for 443.

Requires Python 3.6+.
"""
import sys
import socket
import ssl
import argparse
from datetime import datetime
import ipaddress

DEFAULT_TIMEOUT = 2.0
DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_READ_TIMEOUT = 3.0
DEFAULT_RETRY_ATTEMPTS = 2
DEFAULT_RETRY_DELAY = 0.5

# Cloudflare IPv4 ranges (common list)
CF_IPV4_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

CF_NETWORKS = [ipaddress.ip_network(n) for n in CF_IPV4_RANGES]


def is_ip_cloudflare(ips):
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
            for net in CF_NETWORKS:
                if a in net:
                    return True
        except Exception:
            continue
    return False


# Cloudflare CNAME patterns for detection
CLOUDFLARE_CNAME_PATTERNS = [
    ".cdn.cloudflare.net",
    ".cloudflare.net",
    ".cloudflare.com",
    ".cloudflaressl.com",
]

# Cloudflare HTTP headers for detection
CLOUDFLARE_HEADERS = {
    "server": ["cloudflare", "cloudflare-nginx"],
    "cf-ray": [".*"],  # Any CF-Ray header indicates Cloudflare
    "cf-cache-status": [".*"],
    "cf-request-id": [".*"],
    "cf-worker": [".*"],
    "cf-polished": [".*"],
}


def detect_cloudflare(ips, cname, headers):
    """
    Enhanced Cloudflare detection using multiple methods.
    Returns a dictionary with detection results and confidence.
    """
    detection_methods = []
    confidence_score = 0

    # Method 1: IP range matching (high confidence)
    ip_match = is_ip_cloudflare(ips)
    if ip_match:
        detection_methods.append(
            {"method": "ip_range", "confidence": 90, "evidence": f"IP in Cloudflare ranges: {ips}"}
        )
        confidence_score += 90

    # Method 2: CNAME pattern matching (high confidence)
    cname_match = False
    cname_evidence = None
    if cname:
        cname_lower = cname.lower()
        for pattern in CLOUDFLARE_CNAME_PATTERNS:
            if pattern in cname_lower:
                cname_match = True
                cname_evidence = f"CNAME contains {pattern}"
                break

    if cname_match:
        detection_methods.append(
            {"method": "cname_pattern", "confidence": 85, "evidence": cname_evidence}
        )
        confidence_score += 85

    # Method 3: HTTP header detection (medium confidence)
    header_match = False
    header_evidence = []

    if headers and isinstance(headers, dict):
        for header_name, patterns in CLOUDFLARE_HEADERS.items():
            header_value = headers.get(header_name)
            if header_value:
                header_value_lower = header_value.lower()
                for pattern in patterns:
                    if pattern == ".*" or pattern in header_value_lower:
                        header_match = True
                        header_evidence.append(f"{header_name}: {header_value}")
                        break  # Found a matching pattern for this header

    if header_match:
        detection_methods.append(
            {
                "method": "http_headers",
                "confidence": 75,
                "evidence": ", ".join(header_evidence[:3]),  # Limit evidence length
            }
        )
        confidence_score += 75

    # Determine overall detection and confidence level
    detected = len(detection_methods) > 0
    if detected:
        # Average confidence if multiple methods
        if len(detection_methods) > 1:
            confidence_score = confidence_score // len(detection_methods)

        # Assign confidence level
        if confidence_score >= 80:
            confidence_level = "high"
        elif confidence_score >= 60:
            confidence_level = "medium"
        else:
            confidence_level = "low"
    else:
        confidence_level = "none"
        confidence_score = 0

    return {
        "detected": detected,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "methods": detection_methods,
        "ip_match": ip_match,
        "cname_match": cname_match,
        "header_match": header_match,
    }


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        return ips, None
    except Exception as e:
        return [], str(e)


def get_cname(host):
    """Return CNAME target (string, without trailing dot) if present, or None.
    Uses dnspython if available; otherwise tries a dig subprocess fallback.
    """
    # prefer dnspython if installed
    try:
        import dns.resolver
        import dns.exception

        try:
            ans = dns.resolver.resolve(host, "CNAME", raise_on_no_answer=False)
            if ans.rrset:
                return str(ans[0]).rstrip(".")
        except dns.exception.DNSException:
            pass
    except Exception:
        pass

    # fallback: try calling dig if available
    try:
        import subprocess

        out = subprocess.check_output(
            ["dig", "+short", "CNAME", host], stderr=subprocess.DEVNULL, timeout=2
        )
        s = out.decode("utf-8").strip()
        if s:
            return s.splitlines()[0].rstrip(".")
    except Exception:
        pass

    # last-resort fallback: try socket aliases
    try:
        h, aliases, ips = socket.gethostbyname_ex(host)
        if aliases:
            return aliases[0]
    except Exception:
        pass
    return None


def tcp_connect(host, port, timeout):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return sock, None
    except Exception as e:
        return None, str(e)


def tcp_connect_with_retry(host, port, timeout, retry_attempts=0, retry_delay=0.5):
    """
    Attempt TCP connection with retry logic.

    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout per attempt
        retry_attempts: Number of retry attempts (0 means no retry)
        retry_delay: Delay between retries in seconds

    Returns:
        (socket, error) tuple
    """
    last_error = None
    for attempt in range(retry_attempts + 1):  # +1 for initial attempt
        if attempt > 0:
            # Wait before retry (except for first attempt)
            import time

            time.sleep(retry_delay)
            print(f"Retry attempt {attempt} for {host}:{port}...", file=sys.stderr)

        sock, err = tcp_connect(host, port, timeout)
        if sock:
            return sock, None
        last_error = err

    return None, f"All {retry_attempts + 1} connection attempts failed: {last_error}"


def _read_response_headers(sock, timeout):
    sock.settimeout(timeout)
    resp = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if b"\r\n\r\n" in resp:
            break
    if not resp:
        return None, None, None
    try:
        header_part, rest = resp.split(b"\r\n\r\n", 1)
    except ValueError:
        header_part = resp
        rest = b""
    hdr_text = header_part.decode("iso-8859-1", errors="replace")
    lines = hdr_text.split("\r\n")
    status_line = lines[0] if lines else ""
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    # parse status
    status = None
    parts = status_line.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except Exception:
            status = parts[1]
    return status, status_line, headers


def http_head_over_socket(sock, host, is_tls=False, timeout=DEFAULT_TIMEOUT):
    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cloudflare_domain_validator/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        status, status_line, headers = _read_response_headers(sock, timeout)
        return status, status_line, headers
    except Exception as e:
        return None, None, {"error": str(e)}


def http_get_over_socket(sock, host, is_tls=False, timeout=DEFAULT_TIMEOUT, max_body=8192):
    try:
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cloudflare_domain_validator/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        status, status_line, headers = _read_response_headers(sock, timeout)
        # read a small part of body (if any)
        body = b""
        try:
            while len(body) < max_body:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        except Exception:
            pass
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return status, status_line, headers, body_text
    except Exception as e:
        return None, None, {"error": str(e)}, ""


def check_port(host, port, timeout, retry_attempts=0, retry_delay=0.5):
    # Use retry logic if retry_attempts > 0
    if retry_attempts > 0:
        sock, err = tcp_connect_with_retry(host, port, timeout, retry_attempts, retry_delay)
    else:
        sock, err = tcp_connect(host, port, timeout)
    if not sock:
        return {"open": False, "error": err}
    result = {"open": True}
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
            cert = ssl_sock.getpeercert()
            result["tls_ok"] = True
            if cert:
                try:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                except Exception:
                    subject = cert.get("subject")
                try:
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                except Exception:
                    issuer = cert.get("issuer")
                notAfter = cert.get("notAfter")
                result["cert_subject"] = (
                    subject.get("commonName") if isinstance(subject, dict) else subject
                )
                result["cert_issuer"] = (
                    issuer.get("commonName") if isinstance(issuer, dict) else issuer
                )
                result["cert_notAfter"] = notAfter
            else:
                result["cert_subject"] = None
                result["cert_issuer"] = None
                result["cert_notAfter"] = None
            # Try HEAD first
            status, status_line, headers = http_head_over_socket(
                ssl_sock, host, is_tls=True, timeout=timeout
            )
            result["http_status"] = status
            result["http_headers"] = headers
            # If we don't have a numeric status or want the body for classification, try GET
            final_status = status
            body = ""
            if final_status is None or (isinstance(final_status, int) and final_status >= 400):
                # attempt GET to be sure
                try:
                    # reopen a fresh TLS connection to do GET
                    ssl_sock.close()
                    # Use retry logic for the second connection as well
                    if retry_attempts > 0:
                        sock2, err2 = tcp_connect_with_retry(
                            host, port, timeout, retry_attempts, retry_delay
                        )
                    else:
                        sock2, err2 = tcp_connect(host, port, timeout)
                    if sock2:
                        ssl_sock2 = ctx.wrap_socket(sock2, server_hostname=host)
                        st, stline, hdrs, body = http_get_over_socket(
                            ssl_sock2, host, is_tls=True, timeout=timeout
                        )
                        final_status = st
                        result["http_headers"] = hdrs
                        try:
                            ssl_sock2.close()
                        except Exception:
                            pass
                except Exception:
                    pass
            result["final_http_status"] = final_status
            # classify
            if final_status == 200:
                result["status_label"] = "200 OK"
            elif final_status == 404:
                result["status_label"] = "404 Not Found"
            elif final_status == 401:
                result["status_label"] = "401 Unauthorized"
            elif final_status == 403:
                result["status_label"] = "403 Forbidden"
            elif final_status is None:
                result["status_label"] = "no-response"
            else:
                result["status_label"] = f"other-{final_status}"
            try:
                ssl_sock.close()
            except Exception:
                pass
        except ssl.SSLError as e:
            result["tls_ok"] = False
            result["tls_error"] = str(e)
            try:
                sock.close()
            except:
                pass
        except Exception as e:
            result["tls_ok"] = False
            result["tls_error"] = str(e)
            try:
                sock.close()
            except:
                pass
    else:
        try:
            status, status_line, headers = http_head_over_socket(
                sock, host, is_tls=False, timeout=timeout
            )
            result["http_status"] = status
            result["http_headers"] = headers
            # detect redirect to https
            loc = None
            if headers and isinstance(headers, dict):
                loc = headers.get("location")
            if status in (301, 302, 307, 308) and loc:
                # simple check if Location points to https
                if (
                    loc.startswith("https://")
                    or loc.startswith("//")
                    or (loc.startswith("http://") and "443" in loc)
                ):
                    result["redirects_to_https"] = True
                    result["redirect_location"] = loc
                else:
                    result["redirects_to_https"] = False
                    result["redirect_location"] = loc
            else:
                result["redirects_to_https"] = False
            sock.close()
        except Exception as e:
            result["http_status"] = None
            result["http_error"] = str(e)
            try:
                sock.close()
            except:
                pass
    return result


def parse_args():
    p = argparse.ArgumentParser(
        description="Check domain accessibility on ports 80 and 443 with enhanced Cloudflare detection"
    )
    p.add_argument("domains", nargs="*", help="Domains to check")
    p.add_argument("-f", "--file", help="File with domains (one per line)")
    p.add_argument("-o", "--output", help="Output file (default: stdout)")
    p.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument(
        "--parallel-workers",
        type=int,
        default=3,
        help="Number of parallel domain checks (default: 3)",
    )
    p.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    p.add_argument(
        "--read-timeout",
        type=float,
        default=DEFAULT_READ_TIMEOUT,
        help=f"Read timeout in seconds (default: {DEFAULT_READ_TIMEOUT})",
    )
    p.add_argument(
        "--retry-attempts",
        type=int,
        default=DEFAULT_RETRY_ATTEMPTS,
        help=f"Number of retry attempts for failed connections (default: {DEFAULT_RETRY_ATTEMPTS})",
    )
    p.add_argument(
        "--retry-delay",
        type=float,
        default=DEFAULT_RETRY_DELAY,
        help=f"Delay between retries in seconds (default: {DEFAULT_RETRY_DELAY})",
    )
    p.add_argument("--no-retry", action="store_true", help="Disable retry logic")
    return p.parse_args()


def pretty_print(domain, ips, res80, res443):
    print(f"Domain: {domain}")
    if ips:
        print(f"  Resolved IPs: {', '.join(ips)}")
    else:
        print(f"  Resolved IPs: (none / resolution failed)")
    print("  Port 80 (HTTP):")
    if not res80["open"]:
        print(f"    TCP: closed / failed -> {res80.get('error')}")
    else:
        print("    TCP: open")
        if res80.get("http_status") is not None:
            print(f"    HTTP: {res80['http_status']}  {res80.get('http_status_line') or ''}")
        else:
            print(f"    HTTP: no valid HTTP response (error: {res80.get('http_error')})")
    print("  Port 443 (HTTPS):")
    if not res443["open"]:
        print(f"    TCP: closed / failed -> {res443.get('error')}")
    else:
        print("    TCP: open")
        if res443.get("tls_ok"):
            print("    TLS: handshake OK")
            subj = res443.get("cert_subject")
            issuer = res443.get("cert_issuer")
            na = res443.get("cert_notAfter")
            if na:
                try:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                    na_str = exp.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    na_str = na
            else:
                na_str = None
            print(f"      cert subject: {subj}")
            print(f"      cert issuer:  {issuer}")
            print(f"      cert expires: {na_str}")
        else:
            print(f"    TLS: handshake failed -> {res443.get('tls_error')}")
        if res443.get("http_status") is not None:
            print(
                f"    HTTP over TLS: {res443['http_status']}  {res443.get('http_status_line') or ''}"
            )
        else:
            if res443.get("tls_ok"):
                print(f"    HTTP over TLS: no valid HTTP response")
    print("-" * 60)


def print_table(results):
    # columns: Domain, CNAME, IPs, Port80, Port443, Redirect80->443, HTTPS_200, Page, Cloudflare
    headers = [
        "Domain",
        "CNAME",
        "IPs",
        "Port80",
        "Port443",
        "80->443",
        "HTTPS_200",
        "Page",
        "Cloudflare",
    ]
    rows = []
    for r in results:
        cname = r.get("cname") or "-"
        ips = ",".join(r.get("ips") or []) or "-"
        res80 = r.get("res80", {})
        res443 = r.get("res443", {})
        port80 = "open" if res80.get("open") else "closed"
        port443 = "open" if res443.get("open") else "closed"
        redirects = "yes" if res80.get("redirects_to_https") else "no"
        https_ok = "yes" if (res443.get("final_http_status") == 200) else "no"
        page = res443.get("status_label") or "-"
        # Enhanced Cloudflare detection display
        cf_detection = r.get("cloudflare_detection", {})
        if cf_detection.get("detected"):
            confidence = cf_detection.get("confidence_level", "unknown")
            cf = f"yes-{confidence}"
        else:
            cf = "no"
        rows.append([r["domain"], cname, ips, port80, port443, redirects, https_ok, page, cf])

    # compute column widths
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    col_widths = [max(len(str(x)) for x in col) for col in cols]

    # print header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    sep_line = "-+-".join("-" * w for w in col_widths)
    print(header_line)
    print(sep_line)
    for row in rows:
        print(" | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths)))


def print_cloudflare_summary(results):
    """
    Print detailed Cloudflare detection summary.

    Args:
        results: List of domain probe results
    """
    print("\n" + "=" * 80)
    print("CLOUDFLARE DETECTION SUMMARY")
    print("=" * 80)

    # Group domains by detection status
    cf_domains = []
    non_cf_domains = []

    for r in results:
        cf_detection = r.get("cloudflare_detection", {})
        if cf_detection.get("detected"):
            cf_domains.append(r)
        else:
            non_cf_domains.append(r)

    # Print Cloudflare domains summary
    print(f"\nCloudflare Detected: {len(cf_domains)} domains")
    print("-" * 40)

    if cf_domains:
        # Group by confidence level
        high_conf = []
        medium_conf = []
        low_conf = []

        for r in cf_domains:
            cf_detection = r.get("cloudflare_detection", {})
            confidence = cf_detection.get("confidence_level", "unknown")

            if confidence == "high":
                high_conf.append(r)
            elif confidence == "medium":
                medium_conf.append(r)
            elif confidence == "low":
                low_conf.append(r)
            else:
                medium_conf.append(r)  # default

        print(f"  High Confidence ({len(high_conf)}):")
        for r in high_conf:
            cf_detection = r.get("cloudflare_detection", {})
            methods = cf_detection.get("methods", [])
            method_desc = []
            for m in methods:
                if m["method"] == "ip_range":
                    method_desc.append("IP Range")
                elif m["method"] == "cname_pattern":
                    method_desc.append("CNAME Pattern")
                elif m["method"] == "http_headers":
                    method_desc.append("HTTP Headers")
            print(f"    - {r['domain']} (Methods: {', '.join(method_desc)})")

        if medium_conf:
            print(f"\n  Medium Confidence ({len(medium_conf)}):")
            for r in medium_conf:
                print(f"    - {r['domain']}")

        if low_conf:
            print(f"\n  Low Confidence ({len(low_conf)}):")
            for r in low_conf:
                print(f"    - {r['domain']}")

    # Print Non-Cloudflare domains
    print(f"\nNo Cloudflare Detected: {len(non_cf_domains)} domains")
    print("-" * 40)

    if non_cf_domains:
        # Show first 10 non-CF domains
        display_count = min(10, len(non_cf_domains))
        for i in range(display_count):
            r = non_cf_domains[i]
            print(f"  - {r['domain']}")

        if len(non_cf_domains) > display_count:
            print(f"  ... and {len(non_cf_domains) - display_count} more")

    # Detection methods statistics
    print(f"\nDetection Methods Used:")
    print("-" * 40)

    method_counts = {"ip_range": 0, "cname_pattern": 0, "http_headers": 0}

    for r in cf_domains:
        cf_detection = r.get("cloudflare_detection", {})
        methods = cf_detection.get("methods", [])
        for m in methods:
            method_type = m.get("method")
            if method_type in method_counts:
                method_counts[method_type] += 1

    if cf_domains:
        for method, count in method_counts.items():
            if count > 0:
                method_name = {
                    "ip_range": "IP Range Matching",
                    "cname_pattern": "CNAME Pattern",
                    "http_headers": "HTTP Headers",
                }.get(method, method)
                print(f"  {method_name}: {count} domains")

    print("=" * 80)


def output_results(results, output_format="table", output_file=None):
    """
    Output results in specified format to file or stdout.

    Args:
        results: List of domain probe results
        output_format: 'table', 'json', or 'csv'
        output_file: Path to output file (None for stdout)
    """
    import json
    import csv
    import sys

    # Determine output stream
    if output_file:
        f = open(output_file, "w", encoding="utf-8")
    else:
        f = sys.stdout

    try:
        if output_format == "table":
            # Print table
            print_table(results)
            # Print Cloudflare summary after table
            print("\n", file=f)
            print_cloudflare_summary(results)

        elif output_format == "json":
            # Full nested JSON output
            json.dump(results, f, indent=2, default=str)
            print(file=f)  # Add newline

        elif output_format == "csv":
            # Minimal CSV output
            writer = csv.writer(f)
            # CSV headers
            headers = [
                "domain",
                "cname",
                "ips",
                "port80_status",
                "port443_status",
                "redirect_80_to_443",
                "https_200",
                "page",
                "cloudflare",
                "cloudflare_confidence",
            ]
            writer.writerow(headers)

            for r in results:
                cname = r.get("cname") or ""
                ips = ",".join(r.get("ips") or [])
                res80 = r.get("res80", {})
                res443 = r.get("res443", {})
                port80_status = "open" if res80.get("open") else "closed"
                port443_status = "open" if res443.get("open") else "closed"
                redirect_80_to_443 = "yes" if res80.get("redirects_to_https") else "no"
                https_200 = "yes" if (res443.get("final_http_status") == 200) else "no"
                page = res443.get("status_label") or ""

                # Cloudflare detection
                cf_detection = r.get("cloudflare_detection", {})
                cloudflare = "yes" if cf_detection.get("detected") else "no"
                cloudflare_confidence = cf_detection.get("confidence_level", "none")

                writer.writerow(
                    [
                        r["domain"],
                        cname,
                        ips,
                        port80_status,
                        port443_status,
                        redirect_80_to_443,
                        https_200,
                        page,
                        cloudflare,
                        cloudflare_confidence,
                    ]
                )

    finally:
        if output_file:
            f.close()


def probe_domain(d, config=None):
    """
    Probe a single domain with enhanced Cloudflare detection.

    Args:
        d: Domain name
        config: Optional configuration dict with keys:
            - connect_timeout: Connection timeout in seconds
            - read_timeout: Read timeout in seconds
            - retry_attempts: Number of retry attempts
            - retry_delay: Delay between retries in seconds
            - no_retry: Boolean to disable retry logic

    Returns:
        Dictionary with domain probe results including enhanced Cloudflare detection
    """
    if config is None:
        config = {}

    # Extract timeout settings with defaults
    connect_timeout = config.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)
    read_timeout = config.get("read_timeout", DEFAULT_READ_TIMEOUT)

    ips, rerr = resolve(d)
    if rerr:
        ips = []
    cname = get_cname(d)

    # Check ports with configured timeout (use connect_timeout for TCP connections)
    res80 = check_port(
        d,
        80,
        timeout=connect_timeout,
        retry_attempts=config.get("retry_attempts", 0),
        retry_delay=config.get("retry_delay", 0.5),
    )
    res443 = check_port(
        d,
        443,
        timeout=connect_timeout,
        retry_attempts=config.get("retry_attempts", 0),
        retry_delay=config.get("retry_delay", 0.5),
    )

    # If port80 redirects to https but res443 was closed, re-check to get status_label
    if res80.get("redirects_to_https") and not res443.get("open"):
        res443 = check_port(
            d,
            443,
            timeout=connect_timeout,
            retry_attempts=config.get("retry_attempts", 0),
            retry_delay=config.get("retry_delay", 0.5),
        )

    # Collect headers from both port 80 and 443 for Cloudflare detection
    headers = {}
    if res443.get("http_headers"):
        headers.update(res443.get("http_headers", {}))
    elif res80.get("http_headers"):
        headers.update(res80.get("http_headers", {}))

    # Enhanced Cloudflare detection
    cf_detection = detect_cloudflare(ips, cname, headers)

    # Backward compatibility: simple boolean for Cloudflare detection
    cf_bool = cf_detection["detected"]

    return {
        "domain": d,
        "cname": cname,
        "ips": ips,
        "res80": res80,
        "res443": res443,
        "cloudflare": cf_bool,
        "cloudflare_detection": cf_detection,
    }


def main():
    args = parse_args()
    domains = []

    # If user didn't pass --file or domains, but a local 'domains.txt' exists, use it.
    default_list_file = "domains.txt"
    list_file = args.file if getattr(args, "file", None) else None
    if not list_file and not args.domains and __import__("os").path.exists(default_list_file):
        list_file = default_list_file

    if list_file:
        try:
            with open(list_file, "r") as fh:
                for line in fh:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        domains.append(s)
        except Exception as e:
            print(f"Error reading file {list_file}: {e}", file=sys.stderr)
            sys.exit(2)

    # Add any domains passed directly on CLI
    domains.extend(args.domains)

    if not domains:
        print(
            "No domains provided. Put domains in 'domains.txt' or pass them as arguments.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build configuration from command line arguments
    config = {
        "connect_timeout": args.connect_timeout,
        "read_timeout": args.read_timeout,
        "retry_attempts": 0 if args.no_retry else args.retry_attempts,
        "retry_delay": args.retry_delay,
    }

    # Display configuration summary
    print(
        f"Configuration: Connect timeout={config['connect_timeout']}s, "
        f"Read timeout={config['read_timeout']}s, "
        f"Retry attempts={config['retry_attempts']}, "
        f"Retry delay={config['retry_delay']}s",
        file=sys.stderr,
    )

    results = []
    # run domain probes in parallel
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel_workers) as ex:
        # Use lambda to pass config to probe_domain
        for res in ex.map(lambda domain: probe_domain(domain, config), domains):
            results.append(res)

    # Output results based on format and output file
    output_results(results, args.format, args.output)


if __name__ == "__main__":
    main()
