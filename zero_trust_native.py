import ipaddress, socket, ssl, hashlib, time, re
import http.client


def _canon(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _is_forbidden(ip):
    ip = _canon(ip)
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    )


def _is_global(ip):
    ip = _canon(ip)
    return ip.is_global


def _normalize_url(url):
    url = re.sub(r'://::ffff:([0-9.]+)/', r'://[::ffff:\1]/', url)
    return url


def _parse_url(url):
    url = _normalize_url(url)
    m = re.match(r'^(https?)://(\[[^\]]+\]|[^:/]+)(:(\d+))?(/.*)?$', url)
    if not m:
        raise ValueError("URL invalide")
    scheme, host, _, port, path = m.groups()
    host = host.strip('[]')
    port = int(port) if port else (443 if scheme == "https" else 80)
    path = path or "/"
    return scheme, host, port, path


def validate_zero_trust(url: str):
    scheme, host, port, path = _parse_url(url)
    all_ips = set()
    try:
        all_ips.add(ipaddress.ip_address(host))
    except ValueError:
        for res in socket.getaddrinfo(host, None):
            all_ips.add(ipaddress.ip_address(res[4][0]))

    if not all_ips:
        return False, [], "Aucune IP résolue"

    for ip in all_ips:
        if _is_forbidden(ip):
            return False, [], f"IP interdite: {_canon(ip)}"
        if not _is_global(ip):
            return False, [], f"IP non-globale: {_canon(ip)}"

    return True, list(all_ips), "OK"


def zero_trust_get(url: str, timeout: int = 10):
    scheme, host, port, path = _parse_url(url)
    is_allowed, pinned_ips, reason = validate_zero_trust(url)
    if not is_allowed:
        raise ConnectionRefusedError(f"BLOCK: {reason}")

    last_err = None
    ip_to_pin = None
    sock = None
    for candidate in pinned_ips:
        try:
            sock = socket.create_connection((str(candidate), port), timeout=timeout)
            ip_to_pin = candidate
            break
        except OSError as e:
            last_err = e
            continue
    if sock is None:
        raise ConnectionError(f"Aucune IP validée n'est joignable: {last_err}")

    if scheme == "https":
        context = ssl.create_default_context()
        conn_sock = context.wrap_socket(sock, server_hostname=host)
    else:
        conn_sock = sock

    conn = http.client.HTTPConnection(str(ip_to_pin), port, timeout=timeout)
    conn.sock = conn_sock
    conn.request("GET", path, headers={"Host": host, "User-Agent": "ZeroTrustNative/1.0.3"})
    resp = conn.getresponse()
    body = resp.read().decode('utf-8', errors='replace')
    conn.close()
    return resp.status, body


if __name__ == "__main__":
    tests = [
        "http://169.254.169.254/",
        "http://169.254.1.1/",
        "http://100.64.0.1/",
        "http://::ffff:169.254.169.254/",
        "http://[2001:db8::1]/",
        "http://127.0.0.1/",
        "https://www.google.com/",
    ]
    for t in tests:
        try:
            s, b = zero_trust_get(t)
            print(f"ALLOW {t} -> {s}")
        except ConnectionRefusedError as e:
            print(f"BLOCK {t} <- {e}")
        except Exception as e:
            print(f"ERROR {t} <- {e}")
