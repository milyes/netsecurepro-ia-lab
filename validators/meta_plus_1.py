"""
NetSecurePro IA LAB - v1.0.1 Zero-Trust Native
Auteur: Mohammed Ilyes Zoubirou - Montreal
Protocole "Méta + 1" : Canonisation + Attestation + Pinning
Zero Dependance Externe. 100% STDLIB
"""
import ipaddress, socket, hashlib, time, http.client
from urllib.parse import urlsplit

def _canon(ip):
    """Canonisation: Deballe ::ffff:1.2.3.4 -> 1.2.3.4"""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip

def _is_forbidden(ip):
    """Verifie RFC1918, Link-Local, Loopback, etc apres canonisation"""
    ip = _canon(ip)
    return (ip.is_loopback or ip.is_link_local or ip.is_private or
            ip.is_reserved or ip.is_unspecified or ip.is_multicast)

def attest(decision, url, ip, ts, reason=""):
    """Attestation SHA-256 pour AuditVault. Zero dependance crypto"""
    payload = f"{ts}|{decision}|{url}|{ip}|{reason}".encode()
    digest = hashlib.sha256(payload).hexdigest()
    return f"AuditVault[SHA256:{digest}]"

def validate_meta_plus_1(url):
    """Niveau Meta+1: Parse -> Canonise -> Resout -> Verifie"""
    timestamp = str(int(time.time()))
    decision = "ALLOW"
    all_ips = set()
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or "/"
        if not host: raise ValueError("Host invalide")
        
        # 1. Parse direct
        try: all_ips.add(_canon(ipaddress.ip_address(host)))
        except ValueError: pass
        
        # 2. Resolution DNS v4+v6 AVANT decision. Anti DNS Rebinding
        try:
            for res in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
                all_ips.add(_canon(ipaddress.ip_address(res[4][0])))
        except socket.gaierror: pass
        
        if not all_ips: raise ValueError("Aucune IP resolue")
        
        # 3. Verification de toutes les IP
        for r in all_ips:
            if _is_forbidden(r):
                decision = "BLOCK"
                raise ValueError(f"Bloque Meta+1: Adresse interdite {r}")
        
        ip_canon_str = ", ".join(sorted(str(x) for x in all_ips))
        log = attest(decision, url, ip_canon_str, timestamp)
        return True, log, list(all_ips), host, port, path
        
    except Exception as e:
        decision = "BLOCK"
        log = attest(decision, url, ", ".join(str(x) for x in all_ips), timestamp, str(e))
        return False, log, [], "", 0, ""

def meta_plus_1_get(url):
    """Pinning de Connexion: Force le connect() sur l'IP validee. Anti-TOCTOU"""
    allowed, log, pinned_ips, host, port, path = validate_meta_plus_1(url)
    if not allowed: raise Exception(f"[Meta+1 BLOCK] {log}")
    
    ip_to_pin = str(pinned_ips[0])
    conn_class = http.client.HTTPSConnection if url.startswith("https") else http.client.HTTPConnection
    
    # PINNING ICI: on se connecte a l'IP, mais on envoie Host: pour SNI/TLS
    conn = conn_class(ip_to_pin, port, timeout=10)
    conn.putrequest("GET", path)
    conn.putheader("Host", host) 
    conn.endheaders()
    print(f"[ATTEST] {log}")
    return conn.getresponse()
