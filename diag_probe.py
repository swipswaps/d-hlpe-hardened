"""
diag_probe.py — Standalone httpx mTLS diagnostic.

Usage:
    python diag_probe.py --workers 127.0.0.1:8081
    DHLPE_ALLOW_LEGACY_CA=1 python diag_probe.py --workers 127.0.0.1:8081

Citations:
  [22] https://www.python-httpx.org/advanced/ssl/#client-side-certificates
  [23] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
  [24] https://github.com/elastic/elasticsearch/issues/117769
"""

import argparse
import asyncio
import os
import ssl
import sys
import traceback

import httpx


async def run(workers, ca, cert, key, skip_hostname, allow_legacy):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    if allow_legacy:
        try:
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
            print("[diag] VERIFY_X509_STRICT disabled", file=sys.stderr)
        except AttributeError:
            pass
    if skip_hostname:
        ctx.check_hostname = False
        transport = httpx.AsyncHTTPTransport(verify=ctx, cert=(cert, key))
        client = httpx.AsyncClient(transport=transport, timeout=10.0)
    else:
        client = httpx.AsyncClient(verify=ctx, cert=(cert, key), timeout=10.0)

    rc = 0
    for w in workers:
        url = f"https://{w}/heartbeat"
        try:
            r = await client.post(url, timeout=5.0)
            print(f"{url} -> {r.status_code} {r.text}")
        except Exception as e:
            rc = 2
            print(f"{url} FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    await client.aclose()
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", required=True)
    ap.add_argument("--ca", default="certs/ca.crt")
    ap.add_argument("--cert", default="certs/master.crt")
    ap.add_argument("--key", default="certs/master.key")
    ap.add_argument("--skip-hostname", action="store_true",
                    default=os.environ.get("DHLPE_SKIP_HOSTNAME", "0") == "1")
    ap.add_argument("--allow-legacy-ca", action="store_true",
                    default=os.environ.get("DHLPE_ALLOW_LEGACY_CA", "0") == "1")
    args = ap.parse_args()
    rc = asyncio.run(run(
        args.workers.split(","), args.ca, args.cert, args.key,
        args.skip_hostname, args.allow_legacy_ca,
    ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
