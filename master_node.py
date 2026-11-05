"""
master_node.py — HTTPS orchestrator with replay-protected frames.

v3.1 adds:
  - nonce + timestamp in every outbound frame (replay protection)
  - optional --discover via mDNS (RFC 6762)
  - Content-Length cap on the inbound chat route
  - rate limiter keyed on the bearer token, bounded

Citations:
  [3] OWASP LLM Top 10: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  [6] uvicorn: https://www.uvicorn.org/settings/#http
  [14] OWASP replay: https://github.com/OWASP/CheatSheetSeries
  [17] FastAPI lifespan: https://fastapi.tiangolo.com/advanced/events/
  [22] httpx cert: https://www.python-httpx.org/advanced/ssl/#client-side-certificates
  [23] RFC 5280 keyUsage: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
  [26] httpx limits: https://www.python-httpx.org/advanced/resource-limits/
"""

import argparse
import asyncio
import hashlib
import hmac
import os
import ssl
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import List

import httpx
import numpy as np
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request

from protocol import CMD_COMPUTE, decode_frame, encode_frame
from security_fence import SecurityFence

workers: List[str] = []
security_fence: SecurityFence = None
shared_secret_str: str = ""
http_client: httpx.AsyncClient = None
probe_task: asyncio.Task = None
worker_health: dict = {}
last_probe_error: str = ""
MAX_TOKENS_HARD_CAP = 4096
MAX_PROMPT_CHARS = int(os.environ.get("DHLPE_MAX_PROMPT_CHARS", "32768"))
MAX_BODY_BYTES = int(os.environ.get("DHLPE_MAX_BODY_BYTES", str(16 * 1024 * 1024)))

_ca_path = "certs/ca.crt"
_cert_path = "certs/master.crt"
_key_path = "certs/master.key"


async def probe_workers():
    global last_probe_error
    print(f"[probe] started; workers={workers}", file=sys.stderr)
    while True:
        for w in workers:
            try:
                r = await http_client.post(f"https://{w}/heartbeat", timeout=5.0)
                worker_health[w] = r.status_code == 200
                print(f"[probe] {w} -> {r.status_code}", file=sys.stderr)
            except Exception as e:
                worker_health[w] = False
                last_probe_error = f"{type(e).__name__}: {e}"
                print(f"[probe] {w} FAILED: {last_probe_error}", file=sys.stderr)
        await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, probe_task
    ctx = ssl.create_default_context(cafile=_ca_path)
    ctx.load_cert_chain(_cert_path, _key_path)

    if os.environ.get("DHLPE_ALLOW_LEGACY_CA", "0") == "1":
        try:
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
            print("[tls] VERIFY_X509_STRICT disabled (legacy CA)", file=sys.stderr)
        except AttributeError:
            pass

    limits = httpx.Limits(max_keepalive_connections=5, keepalive_expiry=20.0)

    if os.environ.get("DHLPE_SKIP_HOSTNAME", "1") == "1":
        ctx.check_hostname = False
        transport = httpx.AsyncHTTPTransport(
            verify=ctx, cert=(_cert_path, _key_path), limits=limits
        )
        http_client = httpx.AsyncClient(transport=transport, timeout=30.0)
    else:
        http_client = httpx.AsyncClient(
            verify=ctx, cert=(_cert_path, _key_path), timeout=30.0, limits=limits
        )
    probe_task = asyncio.create_task(probe_workers())
    try:
        yield
    finally:
        probe_task.cancel()
        try:
            await probe_task
        except asyncio.CancelledError:
            pass
        await http_client.aclose()


app = FastAPI(title="D-HLPE Master v3.1", lifespan=lifespan)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    if not hmac.compare_digest(token.encode(), shared_secret_str.encode()):
        raise HTTPException(status_code=403, detail="invalid cluster secret")

    if not security_fence.check_rate_limit("token:" + token):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="body too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="bad Content-Length")

    body = await request.json()
    messages = body.get("messages", [])
    prompt = messages[-1].get("content", "") if messages else ""
    if len(prompt) > MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"prompt exceeds {MAX_PROMPT_CHARS} characters",
        )
    max_tokens = int(body.get("max_tokens", 256))
    if max_tokens > MAX_TOKENS_HARD_CAP:
        raise HTTPException(
            status_code=400,
            detail=f"max_tokens exceeds hard cap {MAX_TOKENS_HARD_CAP}",
        )

    session_id = str(uuid.uuid4())
    dummy = np.random.randn(1, 128).astype(np.float32)
    tensor_obj = {
        "shape": list(dummy.shape),
        "dtype": "float32",
        "quant_type": 0,
        "data": dummy.tobytes(),
    }

    # v3.1: nonce + timestamp are inside the signed body.
    payload = {
        "session_id": session_id,
        "layer_idx": 0,
        "tensor": tensor_obj,
        "max_tokens": max_tokens,
        "nonce": uuid.uuid4().hex,
        "timestamp": int(time.time()),
    }
    current_frame = encode_frame(CMD_COMPUTE, payload)

    healthy = [w for w in workers if worker_health.get(w, False)]
    if not healthy:
        detail = "no healthy workers"
        if last_probe_error:
            detail += f" (last probe error: {last_probe_error})"
        raise HTTPException(status_code=503, detail=detail)

    for w in healthy:
        try:
            r = await http_client.post(
                f"https://{w}/compute-slice",
                content=current_frame,
                headers={
                    "X-Node-Id": "master",
                    "X-Signature": hmac.new(
                        shared_secret_str.encode(), current_frame, hashlib.sha256
                    ).hexdigest(),
                    "Content-Type": "application/octet-stream",
                },
            )
            if r.status_code != 200:
                raise HTTPException(
                    status_code=502, detail=f"worker {w} returned {r.status_code}"
                )
            current_frame = r.content
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=503, detail=f"worker {w} unreachable: {e}"
            )

    try:
        _, _ = decode_frame(current_frame)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=f"worker returned bad frame: {e}")

    return {
        "id": f"chatcmpl-{session_id}",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": (
                    f"Processed distributed inference across "
                    f"{len(healthy)} healthy nodes for prompt: '{prompt}'"
                ),
            },
            "finish_reason": "stop",
        }],
    }


def main():
    global workers, shared_secret_str, security_fence, worker_health
    global _ca_path, _cert_path, _key_path

    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", default="")
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--ca", default="certs/ca.crt")
    parser.add_argument("--cert", default="certs/master.crt")
    parser.add_argument("--key", default="certs/master.key")
    args = parser.parse_args()

    workers = [w for w in args.workers.split(",") if w]
    if args.discover:
        try:
            import discovery
            found = discovery.browse(timeout=3.0)
            for f in found:
                if f not in workers:
                    workers.append(f)
            print(f"[discover] found {len(found)}: {found}", file=sys.stderr)
        except Exception as e:
            print(f"[discover] failed: {type(e).__name__}: {e}", file=sys.stderr)
    if not workers:
        print("ERROR: no workers; pass --workers and/or --discover", file=sys.stderr)
        raise SystemExit(2)

    worker_health = {w: True for w in workers}
    shared_secret_str = args.secret
    security_fence = SecurityFence(shared_secret=args.secret)
    _ca_path, _cert_path, _key_path = args.ca, args.cert, args.key

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=args.port,
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        ssl_ca_certs=args.ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        timeout_graceful_shutdown=10,
        timeout_keep_alive=30,
    )


if __name__ == "__main__":
    main()
