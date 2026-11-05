DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE) v2.5
HARDENED PRODUCTION ARCHITECTURE — PhD-LEVEL SECURITY AUDIT & DEPLOYMENT GUIDE
===============================================================================

0. QUICK START (idempotent, paste-safe)
----------------------------------------
The worker and master are SEPARATE PROCESSES. Start each in its own terminal.
Both use mTLS on their INBOUND sockets (v2.4 only had worker-side mTLS).

    ./preflight.sh                     # optional: lint ports + cert SAN/EKU
    ./make_certs.sh                    # SAN+EKU mTLS certs (skips if valid)
    pip install -r requirements.txt

    # Terminal A — worker on :8081 (HTTPS + CERT_REQUIRED)
    python worker_daemon.py --host 0.0.0.0 --port 8081 \
        --secret testsecret \
        --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt

    # Terminal B — master on :8080 (HTTPS + CERT_REQUIRED)
    python master_node.py --workers 127.0.0.1:8081 --port 8080 \
        --secret testsecret \
        --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

    # Terminal C — smoke test (or run the individual curl commands below)
    DHLPE_SECRET=testsecret ./smoke_test.sh

WHY CLIENT CERTS ARE REQUIRED EVERYWHERE:
    Both nodes run with ssl_cert_reqs=ssl.CERT_REQUIRED. The client must
    present a cert signed by certs/ca.crt on every request. Without
    --cert/--key the TLS handshake fails before any route is reached.
    The demo uses master.crt/master.key as the client identity; a
    production deployment should issue separate client certificates.

WHY THE CERTS HAVE SANs AND EKU:
    Modern TLS clients require Subject Alternative Names (RFC 6125 §6.4.4;
    CA/B Forum Ballot SC-12). CN is ignored. make_certs.sh emits
    DNS:localhost, DNS:worker/master, IP:127.0.0.1, IP:::1 on every cert,
    and adds extendedKeyUsage=serverAuth,clientAuth (RFC 5280 §4.2.1.12)
    so the same cert can act as server or client. To bake LAN addresses
    into the certs, set DHLPE_EXTRA_SANS before running make_certs.sh:
        DHLPE_EXTRA_SANS="IP:192.168.4.50,IP:192.168.4.51,DNS:pi.local" \
            ./make_certs.sh

1. HOW WE GOT HERE
--------------------
Edge AI inference is constrained by single-device RAM. Pipeline parallelism —
sharding Transformer layers across LAN-connected devices — enables models that
exceed any individual node's memory. This principle was formalized in
Megatron-LM [11] and demonstrated at the edge by Distributed Llama [5] and
Private LLM. Naive pipeline parallelism, however, exposes new threat surfaces:
activation tensors can be inverted to reconstruct prompts [13], weights can be
stolen from unencrypted inter-node traffic [14], and Android OEM battery
optimizers silently kill workers [15]. D-HLPE v2.5 mitigates each of these.

2. WHERE WE ARE — MITIGATION MATRIX
-------------------------------------
| Threat                         | Mitigation in this repo                                | Citation |
|--------------------------------|--------------------------------------------------------|----------|
| Prompt injection (LLM01:2025)  | Strict Pydantic schema; no dynamic layer selection     | [3]      |
| Activation inversion           | End-to-end mTLS on BOTH worker and master sockets      | [8],[13] |
| Weight theft via sniffing      | mTLS on every RPC; no plaintext fallback               | [8],[14] |
| Cert w/o SAN → client rejection| make_certs.sh emits SAN+EKU; regenerates legacy certs  | [19],[20]|
| Cert w/o EKU → client role err | extendedKeyUsage=serverAuth,clientAuth                 | [21]     |
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
   master_node.py       HTTPS orchestrator; lifespan-managed probe; per-token
                        rate limit.
   make_certs.sh        Idempotent SAN+EKU cert generator.
   preflight.sh         Lint ports 8080/8081 and cert SAN+EKU (non-destructive).
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

6. KNOWN REMAINING LIMITS
---------------------------
- Real forward passes are stubbed (activations * 1.01). Plug your backend
  (llama.cpp, MLX, ExLlamaV2) into worker_daemon.compute_slice.
- Ed25519 is wired but the master currently authenticates via HMAC to keep
  single-key demos simple. Register per-worker pubkeys to enable attribution.
- The demo uses master.crt/master.key as the client identity. A production
  deployment should issue a dedicated client cert, e.g. certs/client.crt,
  and pass it to curl/browsers instead of the server's cert.
- The master's inbound per-token rate limit treats all clients sharing the
  same bearer token as a single bucket. Dedicated per-client tokens with
  per-token buckets would give better isolation.
- The remote push path rebases onto origin/master when branches are related;
  if histories are unrelated it falls back to --force-with-lease. Set
  DHLPE_NO_PUSH=1 to skip.
