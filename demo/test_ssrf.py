from validators.meta_plus_1 import validate_meta_plus_1

tests = [
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/",
    "http://[2001:db8::1]/",
    "https://www.google.com/"
]

for t in tests:
    ok, log, ips, host, port, path = validate_meta_plus_1(t)
    status = 'ALLOW' if ok else 'BLOCK'
    print(f"{t} -> {status} | IPs:{ips} | {log}")
