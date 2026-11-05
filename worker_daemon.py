"""
worker_daemon.py — HTTPS worker with replay protection and bounded intake.

v3.1 adds:
  - rate limit on /heartbeat (was unlimited)
  - nonce + timestamp check after HMAC verification
  - Content-Length cap before reading the body
  - optional mDNS registration

Citations:
  [3] OWASP LLM Top 10: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  [4] llama.cpp RPC: https://github.com/ggml-org/llama.cpp/discussions/9446
  [6] uvicorn: https://www.uvicorn.org/settings/#http
  [14] OWASP replay: https://github.com/OWASP/CheatSheetSeries
  [17] FastAPI lifespan: https://fastapi.tiangolo.com/advanced/events/
  [25] FastAPI Response: https://fastapi.tiangolo.com/advanced/custom-response/
"""

import argparse
import os
import ssl
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict

import numpy as np
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, Response

from protocol import CMD_COMPUTE, CMD_HEARTBEAT, decode_frame, encode_frame
from security_fence import SecurityFence

MAX_KV_ELEMENTS = int(os.environ.get("DHLPE_MAX_KV_ELEMENTS", str(64 * 1024 * 1024)))
MAX_TOKENS_PER_REQUEST = int(os.environ.get("DHLPE_MAX_TOKENS_PER_REQUEST", "1024"))
MAX_BODY_BYTES = int(os.environ.get("DHLPE_MAX_BODY_BYTES", str(16 * 1024 * 1024)))

security_fence: SecurityFence = None
kv_store: Dict[str, Dict[int, tuple]] = {}
_mdns = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    kv_store.clear()
    if _mdns is not None:
        _mdns.close()


app = FastAPI(title="D-HLPE Worker v3.1", lifespan=lifespan)


def _check_body_size(request: Request) -> None:
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="body too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="bad Content-Length")


@app.post("/heartbeat")
async def heartbeat(request: Request, x_client_ip: str = Header("127.0.0.1")):
    # v3.1: heartbeat is now rate-limited too.
    if not security_fence.check_rate_limit("hb:" + x_client_ip):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return {"status": "alive", "ts": time.time(), "sessions": len(kv_store)}


@app.post("/compute-slice")
async def compute_slice(
    request: Request,
    x_signature: str = Header(None),
    x_node_id: str = Header("unknown"),
    x_client_ip: str = Header("127.0.0.1"),
):
    if not security_fence.check_rate_limit("cs:" + x_client_ip):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    _check_body_size(request)
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="body too large")

    sig_bytes = b""
    if x_signature:
        try:
            sig_bytes = bytes.fromhex(x_signature)
        except ValueError:
            raise HTTPException(status_code=403, detail="malformed signature hex")

    ed_ok = security_fence.verify_ed25519(x_node_id, raw, sig_bytes)
    hmac_ok = (
        security_fence.verify_hmac_legacy(raw, x_signature)
        if not ed_ok and x_signature
        else False
    )
    if not (ed_ok or hmac_ok):
        raise HTTPException(status_code=403, detail="authentication failed")

    try:
        cmd, payload = decode_frame(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"bad frame: {e}")

    if cmd == CMD_HEARTBEAT:
        return {"status": "ok"}

    # v3.1: replay protection. Nonce and timestamp are inside the signed body.
    nonce = payload.get("nonce")
    timestamp = payload.get("timestamp")
    if not security_fence.check_nonce(nonce, timestamp):
        raise HTTPException(status_code=409, detail="stale or replayed nonce")

    session_id = payload.get("session_id", str(uuid.uuid4()))
    requested_tokens = int(payload.get("max_tokens", 1))
    if requested_tokens > MAX_TOKENS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=f"max_tokens exceeds worker cap {MAX_TOKENS_PER_REQUEST}",
        )

    tensor_obj = payload.get("tensor", {})
    shape = tensor_obj.get("shape", [])
    quant_type = tensor_obj.get("quant_type", 0)
    data = tensor_obj.get("data", b"")

    if not SecurityFence.validate_tensor_block_alignment(shape, quant_type):
        raise HTTPException(
            status_code=400,
            detail="tensor shape violates quantization block alignment",
        )

    expected = 1
    for dim in shape:
        expected *= dim
    if len(data) != expected * 4:
        raise HTTPException(
            status_code=400,
            detail=f"tensor data length {len(data)} != product(shape)*4 ({expected * 4})",
        )

    activations = np.frombuffer(data, dtype=np.float32).copy().reshape(shape)

    layer_idx = payload.get("layer_idx", 0)
    session = kv_store.setdefault(session_id, {})
    current_elems = (
        sum(k[0].size + k[1].size for k in session.values()) if session else 0
    )
    if current_elems + activations.size > MAX_KV_ELEMENTS:
        raise HTTPException(status_code=507, detail="KV cache capacity exceeded")
    session[layer_idx] = (activations.copy(), activations.copy())

    out = activations * np.float32(1.01)
    out_obj = {
        "shape": list(out.shape),
        "dtype": "float32",
        "quant_type": quant_type,
        "data": out.tobytes(),
    }
    frame = encode_frame(CMD_COMPUTE, {"session_id": session_id, "tensor": out_obj})
    return Response(content=frame, media_type="application/octet-stream")


def main():
    global security_fence, _mdns
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--mdns-name", default="")
    args = parser.parse_args()

    security_fence = SecurityFence(shared_secret=args.secret)

    if args.mdns_name:
        try:
            import discovery
            _mdns = discovery.register(args.port, args.mdns_name)
        except Exception as e:
            print(f"[mdns] registration failed: {type(e).__name__}: {e}")

    uvicorn.run(
        app,
        host=args.host,
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
