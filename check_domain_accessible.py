#!/usr/bin/env python3
"""
check_domain_accessible.py

Usage:
  python3 check_domain_accessible.py example.com [other.com ...]
  python3 check_domain_accessible.py -f domains.txt

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

DEFAULT_TIMEOUT = 1.0

# Cloudflare IPv4 ranges (common list)
CF_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/12",
    "172.64.0.0/13",
    "131.0.72.0/22",
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
        import dns.resolver, dns.exception
        try:
            ans = dns.resolver.resolve(host, 'CNAME', raise_on_no_answer=False)
            if ans.rrset:
                return str(ans[0]).rstrip('.')
        except dns.exception.DNSException:
            pass
    except Exception:
        pass

    # fallback: try calling dig if available
    try:
        import subprocess
        out = subprocess.check_output(['dig', '+short', 'CNAME', host], stderr=subprocess.DEVNULL, timeout=2)
        s = out.decode('utf-8').strip()
        if s:
            return s.splitlines()[0].rstrip('.')
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
    hdr_text = header_part.decode('iso-8859-1', errors='replace')
    lines = hdr_text.split('\r\n')
    status_line = lines[0] if lines else ''
    headers = {}
    for l in lines[1:]:
        if ':' in l:
            k, v = l.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    # parse status
    status = None
    parts = status_line.split()
    if len(parts) >= 2 and parts[0].startswith('HTTP/'):
        try:
            status = int(parts[1])
        except Exception:
            status = parts[1]
    return status, status_line, headers


def http_head_over_socket(sock, host, is_tls=False, timeout=DEFAULT_TIMEOUT):
    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: check_domain_accessible/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode('utf-8'))
        status, status_line, headers = _read_response_headers(sock, timeout)
        return status, status_line, headers
    except Exception as e:
        return None, None, {'error': str(e)}


def http_get_over_socket(sock, host, is_tls=False, timeout=DEFAULT_TIMEOUT, max_body=8192):
    try:
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: check_domain_accessible/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode('utf-8'))
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
            body_text = body.decode('utf-8', errors='replace')
        except Exception:
            body_text = ''
        return status, status_line, headers, body_text
    except Exception as e:
        return None, None, {'error': str(e)}, ''


def check_port(host, port, timeout):
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
                    subject = dict(x[0] for x in cert.get('subject', ()))
                except Exception:
                    subject = cert.get('subject')
                try:
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                except Exception:
                    issuer = cert.get('issuer')
                notAfter = cert.get('notAfter')
                result["cert_subject"] = subject.get('commonName') if isinstance(subject, dict) else subject
                result["cert_issuer"] = issuer.get('commonName') if isinstance(issuer, dict) else issuer
                result["cert_notAfter"] = notAfter
            else:
                result["cert_subject"] = None
                result["cert_issuer"] = None
                result["cert_notAfter"] = None
            # Try HEAD first
            status, status_line, headers = http_head_over_socket(ssl_sock, host, is_tls=True, timeout=timeout)
            result["http_status"] = status
            result["http_headers"] = headers
            # If we don't have a numeric status or want the body for classification, try GET
            final_status = status
            body = ''
            if final_status is None or (isinstance(final_status, int) and final_status >= 400):
                # attempt GET to be sure
                try:
                    # reopen a fresh TLS connection to do GET
                    ssl_sock.close()
                    sock2, err2 = tcp_connect(host, port, timeout)
                    if sock2:
                        ssl_sock2 = ctx.wrap_socket(sock2, server_hostname=host)
                        st, stline, hdrs, body = http_get_over_socket(ssl_sock2, host, is_tls=True, timeout=timeout)
                        final_status = st
                        result['http_headers'] = hdrs
                        try:
                            ssl_sock2.close()
                        except Exception:
                            pass
                except Exception:
                    pass
            result['final_http_status'] = final_status
            # classify
            if final_status == 200:
                result['status_label'] = '200 OK'
            elif final_status == 404:
                result['status_label'] = '404 Not Found'
            elif final_status == 401:
                result['status_label'] = '401 Unauthorized'
            elif final_status == 403:
                result['status_label'] = '403 Forbidden'
            elif final_status is None:
                result['status_label'] = 'no-response'
            else:
                result['status_label'] = f'other-{final_status}'
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
            status, status_line, headers = http_head_over_socket(sock, host, is_tls=False, timeout=timeout)
            result["http_status"] = status
            result["http_headers"] = headers
            # detect redirect to https
            loc = None
            if headers and isinstance(headers, dict):
                loc = headers.get('location')
            if status in (301,302,307,308) and loc:
                # simple check if Location points to https
                if loc.startswith('https://') or loc.startswith('//') or (loc.startswith('http://') and '443' in loc):
                    result['redirects_to_https'] = True
                    result['redirect_location'] = loc
                else:
                    result['redirects_to_https'] = False
                    result['redirect_location'] = loc
            else:
                result['redirects_to_https'] = False
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
    p = argparse.ArgumentParser(description="Check domain accessibility on ports 80 and 443")
    p.add_argument('domains', nargs='*', help='Domains to check')
    p.add_argument('-f', '--file', help='File with domains (one per line)')
    # Timeout is fixed to DEFAULT_TIMEOUT (5 seconds) and cannot be changed via CLI
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
            print(f"    HTTP over TLS: {res443['http_status']}  {res443.get('http_status_line') or ''}")
        else:
            if res443.get("tls_ok"):
                print(f"    HTTP over TLS: no valid HTTP response")
    print("-" * 60)


def print_table(results):
    # columns: Domain, CNAME, IPs, Port80, Port443, Redirect80->443, HTTPS_200, Page, Cloudflare
    headers = ["Domain", "CNAME", "IPs", "Port80", "Port443", "80->443", "HTTPS_200", "Page", "Cloudflare"]
    rows = []
    for r in results:
        cname = r.get('cname') or '-'
        ips = ",".join(r.get('ips') or []) or "-"
        res80 = r.get('res80', {})
        res443 = r.get('res443', {})
        port80 = "open" if res80.get('open') else "closed"
        port443 = "open" if res443.get('open') else "closed"
        redirects = "yes" if res80.get('redirects_to_https') else "no"
        https_ok = "yes" if (res443.get('final_http_status') == 200) else "no"
        page = res443.get('status_label') or '-'
        cf = "yes" if r.get('cloudflare') else "no"
        rows.append([r['domain'], cname, ips, port80, port443, redirects, https_ok, page, cf])

    # compute column widths
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    col_widths = [max(len(str(x)) for x in col) for col in cols]

    # print header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    sep_line = "-+-".join('-' * w for w in col_widths)
    print(header_line)
    print(sep_line)
    for row in rows:
        print(" | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths)))


def probe_domain(d):
    ips, rerr = resolve(d)
    if rerr:
        ips = []
    cname = get_cname(d)
    res80 = check_port(d, 80, timeout=DEFAULT_TIMEOUT)
    res443 = check_port(d, 443, timeout=DEFAULT_TIMEOUT)
    # If port80 redirects to https but res443 was closed, re-check to get status_label
    if res80.get('redirects_to_https') and not res443.get('open'):
        res443 = check_port(d, 443, timeout=DEFAULT_TIMEOUT)
    cf = is_ip_cloudflare(ips)
    return {
        'domain': d,
        'cname': cname,
        'ips': ips,
        'res80': res80,
        'res443': res443,
        'cloudflare': cf,
    }


def main():
    args = parse_args()
    domains = []

    # If user didn't pass --file or domains, but a local 'domains.txt' exists, use it.
    default_list_file = 'domains.txt'
    list_file = args.file if getattr(args, 'file', None) else None
    if not list_file and not args.domains and __import__('os').path.exists(default_list_file):
        list_file = default_list_file

    if list_file:
        try:
            with open(list_file, 'r') as fh:
                for line in fh:
                    s = line.strip()
                    if s and not s.startswith('#'):
                        domains.append(s)
        except Exception as e:
            print(f"Error reading file {list_file}: {e}", file=sys.stderr)
            sys.exit(2)

    # Add any domains passed directly on CLI
    domains.extend(args.domains)

    if not domains:
        print("No domains provided. Put domains in 'domains.txt' or pass them as arguments.", file=sys.stderr)
        sys.exit(1)

    results = []
    # run up to 2 domain probes in parallel
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        for res in ex.map(probe_domain, domains):
            results.append(res)

    # print summary table
    print_table(results)

if __name__ == "__main__":
    main()




