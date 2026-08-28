# NetSecurePro IA Lab - Validateur SSRF Niveau META+1 v1.0.3

Validateur Zero-Trust SSRF 100% Python STDLIB. Conçu et testé sur Termux Android.

## Problème
La plupart des validateurs SSRF se font bypass par:
1.  `169.254.169.254` - IMDS AWS/GCP
2.  `169.254.1.1` - Autre IP Link-Local
3.  `100.64.0.1` - CGNAT Carrier-Grade NAT  
4.  `::ffff:169.254.169.254` - IPv4-mapped IPv6
5.  DNS Rebinding / TOCTOU

## Solution: META+1
1.  **Canonisation**: `::ffff:1.2.3.4` -> `1.2.3.4`
2.  **Résolution**: `socket.getaddrinfo` pour choper v4 + v6
3.  **Cascade IP**: Si 1 IP sur N est interdite = BLOCK total. Anti-DNS Rebinding.
4.  **Filtrage**: Bloque RFC1918, Link-Local, CGNAT, Loopback, ULA, Multicast
5.  **Globalité**: `ip.is_global` pour bloquer `2001:db8::1` et autres IPs de doc
6.  **Pinning**: Connexion TCP directe à l'IP validée. Pas de re-lookup.
7.  **TLS Correct**: SNI = hostname, pas l'IP. Evite `CERTIFICATE_VERIFY_FAILED`

## Testé sur Termux Android
