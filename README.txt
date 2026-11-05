DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE)
README v3.1 -- NONCE REPLAY PROTECTION, mDNS DISCOVERY, BOUNDED INTAKE
=====================================================================

0. DOCUMENT CONTROL
--------------------
Repository : https://github.com/swipswaps/d-hlpe-hardened
Code level : v3.1
Doc level  : v3.1
Status     : hardened single-worker demonstrator. Multi-worker routing
             is still not correct (see M13).

1. CORRECTION TO THE v3.0 AUDIT
--------------------------------
An external audit claimed the repository uses raw http:// links for
node-to-node RPC. That claim is false for HEAD. Every endpoint is https://,
every README reference is https://, and both listeners are created with
ssl_cert_reqs=ssl.CERT_REQUIRED. There is no cleartext transport to
upgrade. The real gaps were replay, discovery, and unbounded intake, and
v3.1 addresses those.

2. WHAT v3.1 ADDS
------------------
S16 Nonce and timestamp replay protection. Every frame carries a nonce and
    a Unix timestamp inside the HMAC-signed body. The worker rejects a
    nonce it has seen before, or a timestamp outside +/-30 s. HMAC proves
    integrity; the nonce proves freshness. OWASP: "include timestamps or
    nonces in messages and reject duplicates".
S17 mDNS discovery. Workers register _dhlpe._tcp.local. via
    python-zeroconf. The master can pass --discover instead of hard-coding
    DHCP-assigned IPs. RFC 6762 defines the protocol; python-zeroconf
    implements it.
S18 Heartbeat rate limit. /heartbeat now goes through the same sliding
    window as /compute-slice. Previously it was unlimited.
S19 Bounded client_history. The rate-limit dict evicts the oldest 1024
    entries when it exceeds 4096 keys, so it cannot grow forever.
S20 Content-Length cap. Both master and worker reject a body larger than
    DHLPE_MAX_BODY_BYTES (default 16 MiB) before reading it.
S21 Malformed hex is 403, not 500. bytes.fromhex is wrapped.

3. HOW TO USE
--------------
INSTALL
  pip install -r requirements.txt
  ./make_certs.sh

WORKER
  python worker_daemon.py --host 0.0.0.0 --port 8081 \
    --secret "$DHLPE_SECRET" \
    --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt \
    --mdns-name worker-1

MASTER -- explicit
  python master_node.py --workers 192.168.4.24:8081 --port 8080 \
    --secret "$DHLPE_SECRET" \
    --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

MASTER -- discovered
  python master_node.py --discover --port 8080 \
    --secret "$DHLPE_SECRET" \
    --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

4. WHAT IS STILL MISSING
--------------------------
M1  check_hostname is still False by default.
M2  One certificate serves three roles.
M3  HMAC key equals the API bearer token.
M4  Ed25519 is wired but no public keys are registered.
M6  Rate-limit key is still X-Client-Ip, which the client supplies.
M9  KV cache has no TTL or eviction.
M10 No circuit breaker, backoff, or bulkhead.
M11 No seccomp / Landlock / systemd isolation.
M12 No hashes, SBOM, cosign, or SLSA provenance.
M13 Multi-worker frame still drops layer_idx and max_tokens.
M14 No structured audit trail.
M15 No pytest suite or CI.
M16 No LICENSE.
M17 No SECURITY.md.
M18 Secrets still on the command line.

5. CITATIONS
-------------
RFC 2104 HMAC: https://datatracker.ietf.org/doc/html/rfc2104
RFC 5280 keyUsage: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
RFC 6762 mDNS: https://www.rfc-editor.org/rfc/rfc6762
RFC 8032 Ed25519: https://datatracker.ietf.org/doc/html/rfc8032
RFC 9110 HTTP semantics: https://datatracker.ietf.org/doc/html/rfc9110
OWASP LLM Top 10: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
OWASP CheatSheetSeries (replay): https://github.com/OWASP/CheatSheetSeries
python-zeroconf: https://pypi.org/project/zeroconf/
uvicorn keepalive: https://www.uvicorn.org/settings/#http
httpx certs: https://www.python-httpx.org/advanced/ssl/#client-side-certificates
httpx limits: https://www.python-httpx.org/advanced/resource-limits/
llama.cpp RPC: https://github.com/ggml-org/llama.cpp/discussions/9446
GitHub mirror docs: https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository
