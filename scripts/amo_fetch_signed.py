#!/usr/bin/env python3
"""Download the AMO-signed .xpi for an already-submitted extension version.

AMO signs each version once; when `web-ext sign` reports the version already
exists (an earlier run or a manual upload), this fetches that signed file.

Usage: amo_fetch_signed.py VERSION OUT_PATH
Env:   AMO_JWT_ISSUER, AMO_JWT_SECRET
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

GUID = "argus@metril.github.io"


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwt() -> str:
    now = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "iss": os.environ["AMO_JWT_ISSUER"],
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
    }).encode())
    msg = header + b"." + payload
    sig = hmac.new(os.environ["AMO_JWT_SECRET"].encode(), msg, hashlib.sha256).digest()
    return (msg + b"." + _b64(sig)).decode()


def get(url: str):
    req = urllib.request.Request(url, headers={"Authorization": "JWT " + jwt()})
    return urllib.request.urlopen(req, timeout=60)


def main() -> None:
    version, out = sys.argv[1], sys.argv[2]
    api = f"https://addons.mozilla.org/api/v5/addons/addon/{GUID}/versions/v{version}/"
    for _ in range(30):
        try:
            f = json.load(get(api)).get("file") or {}
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                sys.exit(f"AMO lookup failed: HTTP {e.code} for {version}")
            print("AMO HTTP", e.code, "- retrying")
            time.sleep(20)
            continue
        except urllib.error.URLError as e:
            print("AMO unreachable:", e.reason, "- retrying")
            time.sleep(20)
            continue
        if f.get("status") == "disabled":
            sys.exit(f"version {version} is disabled on AMO")
        if f.get("status") == "public" and f.get("url"):
            with open(out, "wb") as fh:
                fh.write(get(f["url"]).read())
            print("downloaded", f["url"])
            return
        print("file status:", f.get("status"), "- waiting")
        time.sleep(20)
    sys.exit("signed file not available from AMO")


if __name__ == "__main__":
    main()
