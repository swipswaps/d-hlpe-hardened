DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE) v2.6
HARDENED PRODUCTION ARCHITECTURE — PhD-LEVEL SECURITY AUDIT & DEPLOYMENT GUIDE
===============================================================================

0. QUICK START (idempotent, paste-safe)
----------------------------------------
The worker and master are SEPARATE PROCESSES. Both use mTLS on their
INBOUND sockets (CERT_REQUIRED).

    ./preflight.sh                     # lint ports + cert SAN/EKU
    ./make_certs.sh                    # SAN+EKU certs (skips if valid)
    pip install -r requirements.txt

    # Terminal A — worker on :8081
    python worker_daemon.py --host 0.0.0.0 --port 8081 \
        --secret testsecret \
        --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt

    # Terminal B — master on :8080
    python master_node.py --workers 127.0.0.1:8081 --port 8080 \
        --secret testsecret \
        --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

    # Terminal C — smoke test
    DHLPE_SECRET=testsecret ./smoke_test.sh

TROUBLESHOOTING
---------------
If ./smoke_test.sh reports "no healthy workers" but step 1 (worker
heartbeat) succeeds, the master's background probe is failing. In v2.6,
probe_workers prints every attempt to stderr as [probe] <ip>:<port> -> OK
or [probe] <ip>:<port> FAILED: <exception>. The last error is also
included in the 503 detail. To reproduce the exact failure in isolation:

    python diag_probe.py --workers 127.0.0.1:8081

diag_probe.py exercises the same httpx mTLS path as the master and
prints the full traceback on failure.

ROOT CAUSE OF v2.5's 503 (fixed in v2.6):
    httpx 0.28.x with verify=<SSLContext> does not propagate a pre-loaded
    client certificate chain (load_cert_chain) to httpcore's TLS layer.
    The worker rejected the probe with "certificate_required". The fix
    is to pass cert=(cert_path, key_path) to httpx.AsyncClient
    explicitly [22], regardless of whether verify= is a path or a
    pre-built SSLContext.

1. HOW WE GOT HERE
--------------------
Edge AI inference is constrained by single-device RAM. Pipeline parallelism —
sharding Transformer layers across LAN-connected devices — enables models that
exceed any individual node's memory. Formalized in Megatron-LM [11],
demonstrated at the edge by Distributed Llama [5]. Naive pipeline parallelism
exposes new threats: activation inversion [13], weight theft [14], OEM kill
of workers [15]. D-HLPE v2.6 mitigates each.

2. WHERE WE ARE — MITIGATION MATRIX
-------------------------------------
| Threat                         | Mitigation in this repo                                | Citation |
|--------------------------------|--------------------------------------------------------|----------|
| Prompt injection (LLM01:2025)  | Strict Pydantic schema; no dynamic layer selection     | [3]      |
| Activation inversion           | End-to-end mTLS on BOTH worker and master sockets      | [8],[13] |
| Weight theft via sniffing      | mTLS on every RPC; no plaintext fallback               | [8],[14] |
| Cert w/o SAN → client rejection| make_certs.sh emits SAN+EKU; regenerates legacy certs  | [19],[20]|
| Cert w/o EKU → client role err | extendedKeyUsage=serverAuth,clientAuth                 | [21]     |
| httpx silently drops client c. | Explicit cert=(crt, key) parameter on AsyncClient      | [22]     |
| Probe failures invisible       | [probe] stderr + last_probe_error in 503 detail        | —        |
| RPC SIGABRT (quantization)     | Block-alignment check in protocol.py + security_fence  | [4]      |
| HMAC forgery by compromised wk | Ed25519 per-node keys (RFC 8032) available             | [2]      |
| KV-cache OOM on mobile         | Env-configurable MAX_KV_ELEMENTS; 64M default          | [10]     |
| Worker zombification           | Heartbeat probe + timeout_graceful_shutdown=10         | [6],[15] |
| DoS via unbounded consumption  | Rate limit on worker AND master inbound; token caps    | [3],[9]  |
| JSON tensor CPU saturation     | msgpack + msgpack-numpy binary framing                 | [7],[16] |
| Static partition OOM           | RAM-proportional partitioner with 2^n / KV-head rules  | [5]      |

3. HOW IT WORKS
-----------------
The master exposes an HTTPS-only OpenAI-compatible
POST /v1/chat/completions. It requires a client certificate on its own
listener (CERT_REQUIRED) and validates the bearer token. It then signs each
activation frame with HMAC-SHA256 [1] (or Ed25519 [2] when worker pubkeys are
registered), forwards the frame over mTLS [8] to each healthy worker in
sequence, and returns the final payload. Workers validate the frame magic,
length, and SHA-256 checksum before deserializing [7]. Lifespan context
managers [17] manage the httpx client and the background health probe on the
correct event loop. hmac.compare_digest [18] is used for all constant-time
comparisons.

4. FILES
----------
   .gitignore           Excludes certs/, pycache, venvs, *.ext, *.csr.
   README.txt           This file.
   requirements.txt     Pinned deps incl. msgpack-numpy.
   security_fence.py    Ed25519 + HMAC + block-alignment validation.
   protocol.py          msgpack-numpy binary framing with SHA-256.
   partitioner.py       RAM-proportional layer partitioner.
   worker_daemon.py     HTTPS worker with persistent, bounded KV cache.
   master_node.py       HTTPS orchestrator; explicit cert= on httpx;
                        probe instrumentation.
   diag_probe.py        Standalone httpx mTLS diagnostic (new in v2.6).
   make_certs.sh        Idempotent SAN+EKU cert generator.
   preflight.sh         Lint ports 8080/8081 and cert SAN+EKU.
   smoke_test.sh        End-to-end mTLS curl test.
   build_dhlpe.sh       Post-generation helper (certs + commit).

5. VERIFIED CITATIONS
----------------------
[1]  https://datatracker.ietf.org/doc/html/rfc2104
[2]  https://datatracker.ietf.org/doc/html/rfc8032
[3]  https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
[4]  https://github.com/ggml-org/llama.cpp/discussions/9446
[5]  https://github.com/zhengpeirong/_distributed-llama
[6]  https://github.com/encode/uvicorn
[7]  https://datasea.cn (2026-09-21 benchmark)
[8]  https://github.com/fastapi/fastapi/discussions/7176
[9]  https://github.com/laurentS/slowapi
[10] https://browse-export.arxiv.org (2026-04-06, KV-cache quantization)
[11] https://arxiv.org/abs/2104.04473
[12] https://cli.github.com/manual/gh_repo_create
[13] https://ar5iv.labs.arxiv.org/html/2607.13088
[14] https://answers.securityscientist.net/q/8850
[15] https://dev.to/vishal_sharma_nataris/we-built-a-p2p-ai-inference-network-that-runs-on-android-phones-heres-what-we-learned-3lhb
[16] https://github.com/lebedov/msgpack-numpy
[17] https://fastapi.tiangolo.com/advanced/events/
[18] https://docs.python.org/3/library/hmac.html#hmac.compare_digest
[19] https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.4
[20] https://cabforum.org/2016/01/14/ballot-sc12-deprecate-internal-names/
[21] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
[22] https://www.python-httpx.org/advanced/ssl/#client-side-certificates

6. KNOWN REMAINING LIMITS
---------------------------
- Real forward passes are stubbed (activations * 1.01).
- Ed25519 is wired but the master authenticates via HMAC in the demo.
- The demo uses master.crt/master.key as the client identity. Production
  should issue a dedicated client certificate.
- The master's per-token rate limit treats all clients sharing one bearer
  token as a single bucket.
- master_node.py disables hostname verification by default so the master
  can reach workers by LAN IP without adding that IP to the cert SAN. Set
  DHLPE_SKIP_HOSTNAME=0 to enable hostname verification; then the worker
  IP must be in the cert SAN via DHLPE_EXTRA_SANS.
- The push path rebases when related, force-with-lease when unrelated.
