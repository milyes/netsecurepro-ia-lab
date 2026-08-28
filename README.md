# NetSecurePro IA LAB - v1.0.1
## Protocole "Meta + 1": Validation Reseau Augmentee Zero-Dependency

**Auteur**: Mohammed Ilyes Zoubirou - NetSecurePro IA - Montreal

### Le Probleme: Niveau "Meta"
Les validateurs par regex echouent face a: `::ffff:169.254.169.254`, `0xA9FEA9FE`

### La Solution: Niveau "Meta + 1"
`Canonisation + Resolution + Attestation + Pinning`
1. **Parser**: `urlsplit` pour gerer IPv6
2. **Canoniser**: Deballer `::ffff:1.2.3.4` -> `1.2.3.4`
3. **Resoudre**: `socket.getaddrinfo` v4+v6 AVANT decision. Anti DNS Rebinding
4. **Verifier**: Toutes les IP contre RFC1918, Link-Local, etc.
5. **Attester**: Signature SHA-256 pour AuditVault
6. **Pinner**: Forcer `socket.connect()` sur l'IP validee. Anti TOCTOU

### Installation
Zero dependance. Python 3.8+ uniquement.

```bash
python demo/test_ssrf.py
