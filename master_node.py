"""
master_node.py — Hardened orchestrator with lifespan-managed probe.

Citations:
  [3]  https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  [6]  https://github.com/encode/uvicorn
  [8]  https://github.com/fastapi/fastapi/discussions/7176
  [17] https://fastapi.tiangolo.com/advanced/events/
"""

import argparse
import asyncio
import hashlib
import hmac
import ssl
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
MAX_TOKENS_HARD_CAP = 4096

_ca_path = "certs/ca.crt"
_cert_path = "certs/master.crt"
_key_path = "certs/master.key"


async def probe_workers():
    while True:
        for w in workers:
            try:
                r = await http_client.post(
                    f"https://{w}/heartbeat", timeout=5.0
                )
                worker_health[w] = r.status_code == 200
            except Exception:
                worker_health[w] = False
        await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, probe_task
    ctx = ssl.create_default_context(cafile=_ca_path)
    ctx.load_cert_chain(_cert_path, _key_path)
    # Demo certs use CN=master / CN=worker without SAN IPs; a public
    # deployment should issue SAN certs and set this back to True. [8]
    ctx.check_hostname = False
    http_client = httpx.AsyncClient(verify=ctx, timeout=30.0)
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


app = FastAPI(title="D-HLPE Master v2.3", lifespan=lifespan)


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str = Header(None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    if not hmac.compare_digest(token.encode(), shared_secret_str.encode()):
        raise HTTPException(status_code=403, detail="invalid cluster secret")

    body = await request.json()
    messages = body.get("messages", [])
    prompt = messages[-1].get("content", "") if messages else ""
    max_tokens = int(body.get("max_tokens", 256))
    if max_tokens > MAX_TOKENS_HARD_CAP:  # [3]
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

    payload = {
        "session_id": session_id,
        "layer_idx": 0,
        "tensor": tensor_obj,
        "max_tokens": max_tokens,
    }
    current_frame = encode_frame(CMD_COMPUTE, payload)

    healthy = [w for w in workers if worker_health.get(w, False)]
    if not healthy:
        raise HTTPException(status_code=503, detail="no healthy workers")

    for w in healthy:
        try:
            r = await http_client.post(
                f"https://{w}/compute-slice",
                content=current_frame,
                headers={
                    "X-Node-Id": "master",
                    "X-Signature": hmac.new(
                        shared_secret_str.encode(),
                        current_frame,
                        hashlib.sha256,
                    ).hexdigest(),
                    "Content-Type": "application/octet-stream",
                },
            )
            if r.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"worker {w} returned {r.status_code}",
                )
            current_frame = r.content
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=503, detail=f"worker {w} unreachable: {e}"
            )

    _, final_payload = decode_frame(current_frame)
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
    parser.add_argument("--workers", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--ca", default="certs/ca.crt")
    parser.add_argument("--cert", default="certs/master.crt")
    parser.add_argument("--key", default="certs/master.key")
    args = parser.parse_args()

    workers = args.workers.split(",")
    # Optimistic init: first request routed before first probe completes.
    worker_health = {w: True for w in workers}
    shared_secret_str = args.secret
    security_fence = SecurityFence(shared_secret=args.secret)
    _ca_path, _cert_path, _key_path = args.ca, args.cert, args.key

    uvicorn.run(
        app, host="0.0.0.0", port=args.port, timeout_graceful_shutdown=10
    )


if __name__ == "__main__":
    main()
