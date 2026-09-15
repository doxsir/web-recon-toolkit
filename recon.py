#!/usr/bin/env python3
"""Passive subdomain enumeration via crt.sh (Certificate Transparency).

Local CLI tool. The remote host is hardcoded to https://crt.sh; only a
strictly validated public domain is embedded into the query string. Targets
resolving to private/loopback/link-local IPs are refused.

Results are printed to stdout; redirect to a file if needed:
    python3 recon.py example.com > out.txt
"""
import sys, json, re, ipaddress, socket, http.client, urllib.parse

UA = "web-recon-toolkit/0.1"
CRTSH_HOST = "crt.sh"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))+$")

def is_public_domain(domain):
    if not DOMAIN_RE.match(domain):
        return False
    if domain.endswith((".local", ".internal", ".lan", ".home", ".localhost")) or domain == "localhost":
        return False
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True  # no A record; CT lookup is passive and harmless
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True

def fetch(domain):
    # hardcoded scheme+host, no redirects followed; domain is regex-validated
    path = "/?q=%25." + urllib.parse.quote(domain, safe="") + "&output=json"
    conn = http.client.HTTPSConnection(CRTSH_HOST, timeout=30)
    try:
        conn.request("GET", path, headers={"User-Agent": UA, "Host": CRTSH_HOST})
        resp = conn.getresponse()
        if resp.status != 200:
            sys.exit(f"crt.sh HTTP {resp.status}")
        return json.loads(resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()

def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <public-domain>")
    domain = sys.argv[1].lower().strip()
    if not is_public_domain(domain):
        sys.exit("refusing: not a public domain (or resolves to private/loopback IP)")
    entries = fetch(domain)
    subs = sorted({e["name_value"].lstrip("*.").lower()
                   for e in entries
                   if e.get("name_value") and domain in e["name_value"]})
    print(f"[+] {len(subs)} unique subdomains for {domain}", file=sys.stderr)
    print("\n".join(subs))

if __name__ == "__main__":
    main()
