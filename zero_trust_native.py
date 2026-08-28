import ipaddress, socket, ssl, hashlib, time, re
import http.client

FORBIDDEN_NETS = [
    ipaddress.ip_network("169.254.0.0/16"), # <-- FIX: couvre 169.254.1.1
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"), # <-- FIX: CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _canon(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip

def _is_forbidden(ip):
    ip = _canon(ip)
    return any(ip in net for net in FORBIDDEN_NETS)

def _is_global(ip):
    ip = _canon(ip)
    return ip.is_global

def _normalize_url(url):
    # FIX: http://::ffff:1.2.3.4/ -> http://[::ffff:1.2.3.4]/
    url = re.sub(r'://::ffff:([0-9.]+)/', r'://[::ffff:\1]/', url)
    return url

def _parse_url(url):
    url = _normalize_url(url)
    m = re.match(r'^(https?)://(\[[^\]]+\]|[^:/]+)(:(\d+))?(/.*)?$', url)
    if not m: raise ValueError("URL invalide")
    scheme, host, _, port, path = m.groups()
    host = host.strip('[]')
    port = int(port) if port else (443 if scheme == "https" else 80)
    path = path or "/"
    return scheme, host, port, path

def validate_meta_plus_1(url: str):
    scheme, host, port, path = _parse_url(url)
    all_ips = set()
    try:
        all_ips.add(ipaddress.ip_address(host))
    except ValueError:
        for res in socket.getaddrinfo(host, None):
            all_ips.add(ipaddress.ip_address(res[4][0]))

    # CASCADE IP: Test toutes les IPs. Si 1 est interdite = BLOCK
    for ip in all_ips:
        if _is_forbidden(ip):
            return False, [], f"IP interdite: {_canon(ip)}"
        if not _is_global(ip):
            return False, [], f"IP non-globale: {_canon(ip)}"
            
    return True, list(all_ips), "OK"

def zero_trust_get(url: str, timeout: int = 10):
    scheme, host, port, path = _parse_url(url)
    is_allowed, pinned_ips, reason = validate_meta_plus_1(url)
    if not is_allowed: raise ConnectionRefusedError(f"BLOCK: {reason}")
    ip_to_pin = pinned_ips[0] # Pinning mono-IP pour anti-TOCTOU

    sock = socket.create_connection((str(ip_to_pin), port), timeout=timeout)
    if scheme == "https":
        context = ssl.create_default_context()
        conn_sock = context.wrap_socket(sock, server_hostname=host)
    else:
        conn_sock = sock

    conn = http.client.HTTPConnection(str(ip_to_pin), port, timeout=timeout)
    conn.sock = conn_sock
    conn.request("GET", path, headers={"Host": host, "User-Agent": "ZeroTrustNative/1.0.2"})
    resp = conn.getresponse()
    body = resp.read().decode('utf-8', errors='replace')
    conn.close()
    return resp.status, body

if __name__ == "__main__":
    tests = [ # <-- LES 7 CAS
        "http://169.254.169.254/", # IMDS AWS
        "http://169.254.1.1/", # Bypass Link-local
        "http://100.64.0.1/", # Bypass CGNAT
        "http://::ffff:169.254.169.254/", # Bypass IPv4-mapped
        "http://[2001:db8::1]/", # Bypass Doc IPv6
        "http://127.0.0.1/", # Bypass Loopback
        "https://www.google.com/" # OK
    ]
    for t in tests:
        try:
            s,b = zero_trust_get(t)
            print(f"ALLOW {t} -> {s}")
        except ConnectionRefusedError as e:
            print(f"BLOCK {t} <- {e}")
        except Exception as e:
            print(f"ERROR {t} <- {e}")
