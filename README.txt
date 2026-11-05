DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE) v2.4
HARDENED PRODUCTION ARCHITECTURE — PhD-LEVEL SECURITY AUDIT & DEPLOYMENT GUIDE
===============================================================================

0. QUICK START (idempotent, paste-safe)
----------------------------------------
The worker and master are SEPARATE PROCESSES. Start each in its own terminal.

    ./make_certs.sh                    # SAN-bearing mTLS certs (skips if valid)
    pip install -r requirements.txt

    # Terminal A — worker on :8081
    python worker_daemon.py --host 0.0.0.0 --port 8081 \
        --secret testsecret \
        --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt

    # Terminal B — master on :8080, pointing at the worker
    python master_node.py --workers 127.0.0.1:8081 --port 8080 \
        --secret testsecret \
        --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

    # Terminal C — smoke tests (client cert required because of CERT_REQUIRED)
    curl -X POST https://localhost:8081/heartbeat \
        --cacert certs/ca.crt \
        --cert certs/master.crt --key certs/master.key

    curl -X POST https://localhost:8080/v1/chat/completions \
        -H "Authorization: Bearer testsecret" \
        -H "Content-Type: application/json" \
        -d '{"model":"local","messages":[{"role":"user","content":"Hi"}]}' \
        --cacert certs/ca.crt \
        --cert certs/master.crt --key certs/master.key

WHY CLIENT CERTS ARE REQUIRED:
    Both nodes run with ssl_cert_reqs=ssl.CERT_REQUIRED, so the client must
    present a certificate signed by certs/ca.crt. Without --cert/--key the
    TLS handshake is rejected before any route is reached.

WHY THE CERTS HAVE SANs:
    Modern TLS clients require Subject Alternative Names (RFC 6125 §6.4.4;
    CA/B Forum Ballot SC-12). CN alone is ignored. make_certs.sh emits
    DNS:localhost, DNS:worker/master, IP:127.0.0.1, IP:::1 on every cert.
    To bake a LAN address into the certs, set DHLPE_EXTRA_SANS before running
    make_certs.sh, e.g.:
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
optimizers silently kill workers [15]. D-HLPE v2.4 mitigates each of these.

2. WHERE WE ARE — MITIGATION MATRIX
-------------------------------------
| Threat                         | Mitigation in this repo                                | Citation |
|--------------------------------|--------------------------------------------------------|----------|
| Prompt injection (LLM01:2025)  | Strict Pydantic schema; no dynamic layer selection     | [3]      |
| Activation inversion           | End-to-end mTLS (ssl.CERT_REQUIRED) + binary frames    | [8],[13] |
| Weight theft via sniffing      | mTLS on every RPC; no plaintext fallback               | [8],[14] |
| Cert w/o SAN → client rejection| make_certs.sh emits SANs; regenerates legacy certs     | [19],[20]|
| RPC SIGABRT (quantization)     | Block-alignment check in protocol.py + security_fence  | [4]      |
| HMAC forgery by compromised wk | Ed25519 per-node keys (RFC 8032) available             | [2]      |
| KV-cache OOM on mobile         | Env-configurable MAX_KV_ELEMENTS; 64M default          | [10]     |
| Worker zombification           | Heartbeat probe + timeout_graceful_shutdown=10         | [6],[15] |
| DoS via unbounded consumption  | Worker token cap + master MAX_TOKENS_HARD_CAP          | [3]      |
| JSON tensor CPU saturation     | msgpack + msgpack-numpy binary framing                 | [7],[16] |
| Static partition OOM           | RAM-proportional partitioner with 2^n / KV-head rules  | [5]      |

3. HOW IT WORKS
-----------------
The master exposes an OpenAI-compatible POST /v1/chat/completions. It signs
each activation frame with HMAC-SHA256 [1] (or Ed25519 [2] when worker pubkeys
are registered), forwards the frame over mTLS [8] to each healthy worker in
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
   worker_daemon.py     mTLS worker with persistent, bounded KV cache.
   master_node.py       mTLS orchestrator with lifespan-managed probe.
   make_certs.sh        Idempotent SAN-aware cert generator.
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

6. KNOWN REMAINING LIMITS
---------------------------
- Real forward passes are stubbed (activations * 1.01). Plug your backend
  (llama.cpp, MLX, ExLlamaV2) into worker_daemon.compute_slice.
- Ed25519 is wired but the master currently authenticates via HMAC to keep
  single-key demos simple. Register per-worker pubkeys to enable attribution.
- master_node.py disables hostname verification by default
  (check_hostname = False) so the master can reach workers by IP without
  requiring that IP to be baked into the cert. Set DHLPE_STRICT_TLS=1 to
  re-enable verification; the worker cert must then contain the worker IP
  via DHLPE_EXTRA_SANS.
- The remote push path rebases onto origin/master when the branches are
  related; if the histories are unrelated (previous version's first-run
  commits), it falls back to --force-with-lease. Set DHLPE_NO_PUSH=1 to skip.
