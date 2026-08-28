# Zero Trust Native — Validateur SSRF "Méta+1"

Validateur SSRF minimal, 100% stdlib Python 3.8+, sans dépendance externe.

## Problème résolu

Le filtrage SSRF par regex/string simple (ex: bloquer la chaîne
`"169.254.169.254"`) est contourné par des représentations alternatives
de la même adresse IP, notamment le format IPv4-mapped IPv6 :

```
http://::ffff:169.254.169.254/
```

Un filtre textuel naïf ne reconnaît pas cette forme comme équivalente à
l'IP qu'il cherche à bloquer.

## Approche "Méta+1"

1. **Canonisation** — toute adresse IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
   est déballée vers sa forme IPv4 pure avant toute vérification.
2. **Résolution DNS** — `socket.getaddrinfo` (IPv4 + IPv6) est exécuté
   *avant* la décision de sécurité, sur toutes les IP retournées, pas
   uniquement la première ou la dernière.
3. **Vérification par plage, pas par IP unique** — utilise les
   propriétés natives du module `ipaddress`
   (`is_loopback`, `is_link_local`, `is_private`, `is_reserved`,
   `is_unspecified`, `is_multicast`, `is_global`) plutôt qu'une liste
   manuelle d'adresses. Cela couvre nativement tout le bloc
   `169.254.0.0/16` (pas seulement `169.254.169.254`), la plage de
   documentation IPv6 `2001:db8::/32`, et — via `is_global` en
   complément — le CGNAT partagé `100.64.0.0/10` (RFC 6598), qui
   n'est marqué ni `is_private` ni `is_reserved` par la stdlib.
4. **Pinning de connexion** — la connexion TCP réelle se fait sur
   l'IP déjà validée, jamais sur une nouvelle résolution DNS au
   moment du `connect()` (défense anti DNS-rebinding / TOCTOU).
   Le SNI et le header `Host` conservent le nom d'hôte d'origine
   pour que la vérification du certificat TLS reste correcte.

## Ce qui a été testé

```python
tests = [
    "http://169.254.169.254/",          # BLOCK — endpoint metadata classique
    "http://169.254.1.1/",              # BLOCK — même bloc link-local /16
    "http://::ffff:169.254.169.254/",   # BLOCK — forme IPv4-mapped du même endpoint
    "http://[2001:db8::1]/",            # BLOCK — plage documentation IPv6
    "http://100.64.0.1/",               # BLOCK — CGNAT partagé
    "http://0.0.0.0/",                  # BLOCK — unspecified
    "https://www.google.com/",          # ALLOW — TLS + SNI valides
]
```

Lancer `python3 zero_trust_native.py` pour reproduire.

## Limites connues (documentées volontairement)

- **Pinning mono-IP avec cascade** : parmi les IP résolues et
  validées, la première joignable est utilisée pour la connexion.
  Il n'y a pas de nouvelle résolution DNS après validation — c'est un
  choix délibéré pour éviter de rouvrir une fenêtre TOCTOU, pas un
  oubli. En contrepartie, il n'y a pas de bascule vers une autre IP
  une fois la connexion établie (pas de load-balancing applicatif).
- **Pas d'attestation cryptographique dans cette version** : les
  décisions ne sont pas signées. Si un usage d'audit/traçabilité est
  nécessaire, ajouter un HMAC-SHA256 avec clé secrète autour de
  `(url, ip, decision, timestamp)`.
- **Parsing d'URL par regex** plutôt que `urllib.parse` complet :
  suffisant pour le cas HTTP/HTTPS simple ciblé ici, mais ne couvre
  pas les cas d'URL exotiques (userinfo, IPv6 avec zone scope id, etc.).

## Licence

Voir `LICENSE`.
