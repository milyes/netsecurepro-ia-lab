"""Demo: Test du Protocole Meta+1"""
from validators.meta_plus_1 import validate_meta_plus_1

tests = [
    "http://169.254.169.254/latest/meta-data/", # IMDS AWS/Azure - Doit etre BLOCK
    "http://[::ffff:169.254.169.254]/", # Contournement IPv4-Mapped - Doit etre BLOCK
    "http://[2001:db8::1]/", # Plage DOC IPv6 - Doit etre BLOCK
    "https://www.google.com/" # Public - Doit etre ALLOW
]

print("=== TEST PROTOCOLE META + 1 v1.0.1 ===")
for t in tests:
    ok, log, ips, _, _, _ = validate_meta_plus_1(t)
    status = 'ALLOW' if ok else 'BLOCK'
    print(f"{t} -> {status} | {log}")
