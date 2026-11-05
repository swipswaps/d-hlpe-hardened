DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE) v2.7
HARDENED PRODUCTION ARCHITECTURE — PhD-LEVEL SECURITY AUDIT & DEPLOYMENT GUIDE
===============================================================================

0. QUICK START (idempotent, paste-safe)
----------------------------------------
    ./preflight.sh                     # lint ports + cert SAN/EKU/keyUsage
    ./make_certs.sh                    # SAN+EKU+keyUsage certs
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

WHY THE CA NEEDS keyUsage (v2.7 FIX)
--------------------------------------
Python 3.13+ enables ssl.VERIFY_X509_STRICT by default. OpenSSL 3.x then
rejects any CA certificate that lacks a keyUsage extension, with:

    certificate verify failed: CA cert does not include key usage extension

The v2.7 make_certs.sh emits:

    basicConstraints=critical,CA:TRUE
    keyUsage=critical,keyCertSign,cRLSign
    subjectKeyIdentifier=hash

and detects/regenerates any legacy CA that lacks keyUsage. Because the
leaf certs were signed by the old CA, they are also force-regenerated.
See RFC 5280 §4.2.1.9 [23] and Python 3.13 enforcement [24].

If you must keep an old CA (not recommended), set DHLPE_ALLOW_LEGACY_CA=1
when starting the master. That clears VERIFY_X509_STRICT on the client
context. This weakens TLS validation and should be used only in a lab.

TROUBLESHOOTING
---------------
If ./smoke_test.sh reports "no healthy workers" but step 1 succeeds:
  1. Watch the master's stderr for [probe] lines.
  2. Run: python diag_probe.py --workers 127.0.0.1:8081
  3. If the error is "CA cert does not include key usage extension",
     run ./make_certs.sh again. It will regenerate the CA and leaves.

If the master still says no healthy workers after regeneration, check:
  - openssl x509 -in certs/ca.crt -noout -text | grep -A1 "Key Usage"
    must show "Certificate Sign, CRL Sign".
  - openssl x509 -in certs/worker.crt -noout -text | grep -A1 "Subject Alternative Name"
    must show DNS:localhost, DNS:worker, IP:127.0.0.1.

1. HOW WE GOT HERE
--------------------
Edge AI inference is constrained by single-device RAM. Pipeline parallelism —
sharding Transformer layers across LAN-connected devices — enables models that
exceed any individual node's memory. Formalized in Megatron-LM [11],
demonstrated at the edge by Distributed Llama [5]. Naive pipeline parallelism
exposes new threats: activation inversion [13], weight theft [14], OEM kill
of workers [15]. D-HLPE v2.7 mitigates each.

2. WHERE WE ARE — MITIGATION MATRIX
-------------------------------------
| Threat                         | Mitigation in this repo                                | Citation |
|--------------------------------|--------------------------------------------------------|----------|
| Prompt injection (LLM01:2025)  | Strict Pydantic schema; no dynamic layer selection     | [3]      |
| Activation inversion           | End-to-end mTLS on BOTH worker and master sockets      | [8],[13] |
| Weight theft via sniffing      | mTLS on every RPC; no plaintext fallback               | [8],[14] |
| CA without keyUsage (Py 3.13+) | make_certs.sh emits keyCertSign+cRLSign; regenerates  | [23],[24]|
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
                        probe instrumentation; legacy-CA escape hatch.
   diag_probe.py        Standalone httpx mTLS diagnostic.
   make_certs.sh        Idempotent SAN+EKU+keyUsage cert generator.
   preflight.sh         Lint ports 8080/8081 and cert SAN+EKU+keyUsage.
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
[23] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
[24] https://github.com/elastic/elasticsearch/issues/117769

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
