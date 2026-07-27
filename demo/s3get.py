#!/usr/bin/env python3
"""A minimal SigV4 S3 GET using ONLY the Python standard library.

Used by the s3tap demo to prove capture is library-agnostic: this is a *different*
runtime from curl (Python's `ssl`/OpenSSL 3, via the SSL_*_ex calls) yet s3tap decodes
its GetObject identically. Reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the env.

  usage: s3get.py <endpoint-url> <bucket> <key> [region]
"""
import sys
import os
import hashlib
import hmac
import datetime
import urllib.request
import urllib.parse
import urllib.error


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def s3_get(endpoint: str, bucket: str, key: str, ak: str, sk: str, region: str = "us-east-1"):
    host = urllib.parse.urlparse(endpoint).hostname
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    cr_uri = "/" + bucket + "/" + urllib.parse.quote(key)
    payload_hash = hashlib.sha256(b"").hexdigest()
    canon_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canon_req = f"GET\n{cr_uri}\n\n{canon_headers}\n{signed_headers}\n{payload_hash}"
    scope = f"{datestamp}/{region}/s3/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canon_req.encode()).hexdigest()}"
    k_date = _sign(("AWS4" + sk).encode(), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, "s3")
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, sts.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    req = urllib.request.Request(
        endpoint + cr_uri,
        headers={
            "Authorization": auth,
            "x-amz-date": amzdate,
            "x-amz-content-sha256": payload_hash,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except urllib.error.URLError as e:
        # Connection refused / DNS failure / timeout — return a clean status line instead of
        # an uncaught traceback (the demo redirects our stderr, so a traceback would vanish).
        return f"ERR({e.reason})", 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    endpoint, bucket, key = sys.argv[1], sys.argv[2], sys.argv[3]
    region = sys.argv[4] if len(sys.argv) > 4 else "us-east-1"
    code, n = s3_get(
        endpoint, bucket, key,
        os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"], region,
    )
    print(f"python GET {bucket}/{key} -> {code} ({n} bytes)")
