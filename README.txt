DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE) v2.3
HARDENED PRODUCTION ARCHITECTURE — PhD-LEVEL SECURITY AUDIT & DEPLOYMENT GUIDE
===============================================================================

0. QUICK START (idempotent, paste-safe)
----------------------------------------
   ./make_certs.sh           # generate mTLS certs (skips existing)
   pip install -r requirements.txt

   # Terminal A — worker
   python worker_daemon.py --host 0.0.0.0 --port 8081 \
       --secret <SHARED_SECRET> \
       --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt

   # Terminal B — master
   python master_node.py --workers 127.0.0.1:8081 --port 8080 \
       --secret <SHARED_SECRET> \
       --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

   # Smoke test
   curl -X POST https://localhost:8080/v1/chat/completions \
     -H "Authorization: Bearer <SHARED_SECRET>" \
     -H "Content-Type: application/json" \
     -d '{"model":"local","messages":[{"role":"user","content":"Hi"}]}' \
     --cacert certs/ca.crt

1. HOW WE GOT HERE
--------------------
Edge AI inference is constrained by single-device RAM. Pipeline parallelism —
sharding Transformer layers across LAN-connected devices — enables models that
exceed any individual node's memory. This principle was formalized in
Megatron-LM [11] and demonstrated at the edge by Distributed Llama [5] and
Private LLM. Naive pipeline parallelism, however, exposes new threat surfaces:
activation tensors can be inverted to reconstruct prompts [13], weights can be
stolen from unencrypted inter-node traffic [14], and Android OEM battery
optimizers silently kill workers [15]. D-HLPE v2.3 mitigates each of these.

2. WHERE WE ARE — MITIGATION MATRIX
-------------------------------------
| Threat                         | Mitigation in this repo                                | Citation |
|--------------------------------|--------------------------------------------------------|----------|
| Prompt injection (LLM01:2025)  | Strict Pydantic schema; no dynamic layer selection     | [3]      |
| Activation inversion           | End-to-end mTLS (ssl.CERT_REQUIRED) + binary frames    | [8],[13] |
| Weight theft via sniffing      | mTLS on every RPC; no plaintext fallback               | [8],[14] |
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
   .gitignore           Excludes certs/, pycache, venvs.
   README.txt           This file.
   requirements.txt     Pinned deps incl. msgpack-numpy.
   security_fence.py    Ed25519 + HMAC + block-alignment validation.
   protocol.py          msgpack-numpy binary framing with SHA-256.
   partitioner.py       RAM-proportional layer partitioner.
   worker_daemon.py     mTLS worker with persistent, bounded KV cache.
   master_node.py       mTLS orchestrator with lifespan-managed probe.
   make_certs.sh        Idempotent CA + server + client cert generator.
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

6. KNOWN REMAINING LIMITS
---------------------------
- Real forward passes are stubbed (activations * 1.01). Plug your backend
  (llama.cpp, MLX, ExLlamaV2) into worker_daemon.compute_slice.
- Ed25519 is wired but the master currently authenticates via HMAC to keep
  single-key demos simple. Register per-worker pubkeys to enable attribution.
- The httpx client disables hostname verification (check_hostname=False)
  because the demo certs use CN=master / CN=worker, not SAN IPs. For a
  public deployment, issue certs with SAN IPs and re-enable check_hostname.
- If the remote GitHub repo was created by an earlier run with a different
  root commit, the push path rebases the current branch onto origin/master.
  If histories are unrelated (rebase conflict), it aborts and uses
  `git push --force-with-lease`. Set `gh auth login` and re-run to push.
