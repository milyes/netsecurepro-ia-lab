# NetSecurePro IA LAB - v1.0.1
## Protocole "Méta + 1" : Validation Réseau Augmentée pour RAG Zero-Trust

Auteur : Mohammed Ilyes Zoubirou - NetSecurePro IA - Montréal
Contexte : LABO d'étude sur le vecteur SSRF IPv4-Mapped IPv6 dans Azure AI Search

### Le Problème : Niveau "Méta"
Bloquer `169.254.169.254` avec une regex échoue face à :
`::ffff:169.254.169.254`, `0xA9FEA9FE`, `2852039166`

### La Solution : Niveau "Méta + 1"
Canonisation + Résolution + Attestation + Pinning
1. **Parser** : `urllib.parse.urlsplit` pour gérer IPv6
2. **Canoniser** : Déballer `::ffff:1.2.3.4` -> `1.2.3.4`
3. **Résoudre** : `socket.getaddrinfo` v4+v6 AVANT décision. Anti DNS Rebinding
4. **Vérifier** : Toutes les IP contre RFC1918, Link-Local, etc.
5. **Attester** : Signature SHA-256 + Ed25519 pour AuditVault
6. **Pinner** : Forcer `socket.connect()` sur l'IP validée. Anti TOCTOU

### Installation
```bash
pip install requests cryptography
