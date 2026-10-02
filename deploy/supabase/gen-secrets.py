#!/usr/bin/env python3
"""Generate a fresh secrets file for one self-hosted Supabase stack.

Usage: python3 deploy/supabase/gen-secrets.py <site>
Writes ~/.config/<site>-supabase/secrets.yaml (mode 600). Refuses to overwrite,
since rotating the JWT secret invalidates every issued key and session.
Values are never printed; read them from the file when needed.
"""
import base64, hashlib, hmac, json, os, secrets, sys, time

site = sys.argv[1] if len(sys.argv) == 2 else sys.exit(__doc__)
out = os.path.expanduser(f"~/.config/{site}-supabase/secrets.yaml")
if os.path.exists(out):
    sys.exit(f"{out} already exists; not overwriting")


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(role: str, key: str) -> str:
    now = int(time.time())
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"role": role, "iss": "supabase", "iat": now, "exp": now + 10 * 365 * 86400}).encode())
    sig = b64(hmac.new(key.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


rand = lambda n=32: secrets.token_hex(n)
jwt_secret = rand(32)
values = {
    "jwt": {"secret": jwt_secret, "anonKey": jwt("anon", jwt_secret), "serviceKey": jwt("service_role", jwt_secret)},
    "db": {"password": rand(24), "database": "postgres"},
    "dashboard": {"username": "admin", "password": rand(16), "openAiApiKey": "unused"},
    "analytics": {"publicAccessToken": rand(), "privateAccessToken": rand()},
    "s3": {"keyId": rand(16), "accessKey": rand(32)},
    "realtime": {"secretKeyBase": rand(32), "dbEncKey": rand(8)},
    "meta": {"cryptoKey": rand(16)},
    "smtp": {"username": "unused", "password": "unused"},
}

os.makedirs(os.path.dirname(out), mode=0o700, exist_ok=True)
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("secret:\n")
    for group, kv in values.items():
        f.write(f"  {group}:\n")
        for k, v in kv.items():
            f.write(f'    {k}: "{v}"\n')
print(f"wrote {out}")
