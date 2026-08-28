import ipaddress, socket, hashlib, time, http.client
from urllib.parse import urlsplit

def _canon(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip

def _is_forbidden(ip):
    ip = _canon(ip)
    return (ip.is_loopback or ip.is_link_local or ip.is_private or
            ip.is_reserved or ip.is_unspecified or ip.is_multicast)

def attest(decision, url, ip, ts, reason=""):
    payload = f"{ts}|{decision}|{url}|{ip}|{reason}".encode()
    digest = hashlib.sha256(payload).hexdigest()
    return f"AuditVault[SHA256:{digest[:12]}]"

def validate_meta_plus_1(url):
    timestamp = str(int(time.time()))
    decision = "ALLOW"
    all_ips = set()
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if not host: raise ValueError("Host invalide")
        try: all_ips.add(_canon(ipaddress.ip_address(host)))
        except ValueError: pass
        try:
            for res in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
                all_ips.add(_canon(ipaddress.ip_address(res[4][0])))
        except socket.gaierror: pass
        if not all_ips: raise ValueError("Aucune IP résolue")
        for r in all_ips:
            if _is_forbidden(r):
                decision = "BLOCK"
                raise ValueError(f"Bloqué Méta+1: {r}")
        ip_canon_str = ", ".join(sorted(str(x) for x in all_ips))
        log = attest(decision, url, ip_canon_str, timestamp)
        return True, log, list(all_ips), host, port, parsed.path or "/"
    except Exception as e:
        decision = "BLOCK"
        log = attest(decision, url, ", ".join(str(x) for x in all_ips), timestamp, str(e))
        return False, log, [], "", 0, ""

def meta_plus_1_get(url):
    allowed, log, pinned_ips, host, port, path = validate_meta_plus_1(url)
    if not allowed: raise Exception(f"[Méta+1 BLOCK] {log}")
    ip_to_pin = str(pinned_ips[0])
    conn_class = http.client.HTTPSConnection if url.startswith("https") else http.client.HTTPConnection
    conn = conn_class(ip_to_pin, port, timeout=10)
    conn.putrequest("GET", path)
    conn.putheader("Host", host)
    conn.endheaders()
    print(f"[ATTEST] {log}")
    return conn.getresponse()
