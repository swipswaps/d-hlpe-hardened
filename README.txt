DISTRIBUTED HETEROGENEOUS LLM PIPELINE ENGINE (D-HLPE)
README v3.0 -- ARCHITECTURE, SECURITY POSTURE, AND OPERATIONS MANUAL
=====================================================================

0. DOCUMENT CONTROL
--------------------
Repository : https://github.com/swipswaps/d-hlpe-hardened
Code level : v2.9 (commit 462d4d0)
Doc level  : v3.0
Status     : hardened single-worker demonstrator; multi-worker pipeline
             not yet functional (see section 5, item M13).
Audience   : the operator who runs this on their own hardware and needs to
             know exactly which protections exist, which do not, and how to
             recover or roll back when something fails.

This document is deliberately blunt. A security document that overstates
its controls is worse than no document, because it transfers risk to the
reader without their consent. Where the code does not implement a claim,
the claim is marked NOT IMPLEMENTED and listed in section 5.

1. HOW WE GOT HERE
-------------------
Pipeline parallelism -- splitting a transformer's layers across devices so
that no single device must hold the whole model -- was formalised for GPU
clusters by Narayanan et al. in Megatron-LM (arXiv:2104.04473). They showed
that interleaved pipeline schedules improve throughput by more than 10
percent at comparable memory footprint. Edge ports of the same idea
(Distributed Llama, and the llama.cpp RPC backend) made layer sharding
practical on consumer hardware.

The llama.cpp RPC backend, however, has no authentication. CVE-2026-86317
is a remote assertion failure in rpc_server::deserialize_tensor(), triggered
by a crafted 'ne' argument, exploitable by any host that can reach the port,
with no credential and no user interaction. The upstream project itself
describes the RPC backend as a fragile proof of concept. Running that on a
shared wireless LAN is therefore not a safe default.

D-HLPE keeps the sharding idea and replaces the unauthenticated socket with
mutual TLS, a constant-time HMAC, and a length-prefixed binary frame with a
SHA-256 checksum. The version history is the provenance:

  v2.0  JSON tensor serialisation; HMAC with a nonexistent
        hashlib.compare_digest; stateless KV cache; static 1/N partition;
        no graceful shutdown; no tests.
  v2.1  msgpack framing; expanded ggml quantisation block map.
  v2.2  HMAC fixed to hmac.compare_digest; lifespan-managed probe task;
        probe task reference retained.
  v2.3  Standalone scripts use exit 0 instead of return 0; push path
        rebases before force-with-lease.
  v2.4  Subject Alternative Names on every certificate; client certificate
        added to the smoke-test curl; master inbound switched to HTTPS.
  v2.5  Master uvicorn.run gains ssl_certfile/ssl_keyfile/ssl_ca_certs/
        ssl_cert_reqs; per-token rate limit on the master.
  v2.6  httpx client passes cert=(crt, key) explicitly -- verify=<SSLContext>
        does not reliably carry a loaded client chain.
  v2.7  CA gains keyUsage=critical,keyCertSign,cRLSign, because Python 3.13
        enables ssl.VERIFY_X509_STRICT by default and OpenSSL 3.x then
        rejects any CA without it.
  v2.8  /compute-slice returns Response(media_type="application/octet-
        stream") instead of bare bytes, because FastAPI's jsonable_encoder
        calls bytes.decode() on the SHA-256 digest.
  v2.9  uvicorn timeout_keep_alive raised to 30 s and httpx keepalive_expiry
        set to 20 s, removing the documented keepalive race in which the
        server closes an idle connection just as the client reuses it.

2. WHERE WE ARE
----------------
The running system is two FastAPI processes:

  worker_daemon.py  HTTPS on :8081. Requires a client certificate. Exposes
                    POST /heartbeat and POST /compute-slice. Holds KV state
                    in process memory, bounded by DHLPE_MAX_KV_ELEMENTS.

  master_node.py    HTTPS on :8080. Requires a client certificate. Exposes
                    POST /v1/chat/completions (OpenAI-compatible shape).
                    Runs a background health probe against each worker and
                    forwards HMAC-signed binary frames.

The transport is: TLS 1.3 (forward secret by construction), then a frame
of the form

  MAGIC "DHLP" (4 bytes)
  command (1 byte)
  payload length (8 bytes, big-endian)
  SHA-256 of payload (32 bytes)
  msgpack payload

The worker verifies the magic, the length, and the SHA-256 digest before
deserialising. It then checks the quantisation block alignment of the tensor
shape and the exact byte length before calling np.frombuffer. Both checks
exist specifically to prevent the CVE-2026-86317 class of failure.

What this system is: a single-worker security demonstrator with correct
certificate hygiene, constant-time MAC comparison, binary framing, bounded
memory, bounded tokens, and aligned keepalives. It has been exercised
end-to-end on loopback and returns a valid chatcmpl-* object.

What this system is not: it is not a distributed inference engine. The
layer partitioner exists but is not imported by the master. The master
sends the same small dummy tensor to every worker. Ed25519 verification is
implemented but no public keys are ever registered, so the HMAC path always
wins. The frame does not carry layer_idx or max_tokens across hops, so a
second worker cannot know which slice it owns or what budget applies.

3. HOW TO USE
--------------
PREREQUISITES
  Python 3.11 or newer (3.13+ is recommended; it enables strict X.509
  validation by default).
  openssl on PATH.
  All devices on the same trusted subnet. Do not expose :8080 or :8081 to
  the public internet; the design assumes a trusted LAN and a trusted CA.

INSTALL
  git clone https://github.com/swipswaps/d-hlpe-hardened
  cd d-hlpe-hardened
  ./preflight.sh          # reports port occupancy and certificate health
  ./make_certs.sh         # idempotent; regenerates only what is missing
  pip install -r requirements.txt

RUN -- TERMINAL A (worker)
  python worker_daemon.py \
    --host 0.0.0.0 --port 8081 \
    --secret "$DHLPE_CLUSTER_SECRET" \
    --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt

RUN -- TERMINAL B (master)
  python master_node.py \
    --workers 127.0.0.1:8081 --port 8080 \
    --secret "$DHLPE_CLUSTER_SECRET" \
    --cert certs/master.crt --key certs/master.key --ca certs/ca.crt

RUN -- TERMINAL C (smoke test)
  DHLPE_SECRET="$DHLPE_CLUSTER_SECRET" ./smoke_test.sh

EXPECTED OUTPUT
  Worker log:  "POST /heartbeat HTTP/1.1" 200, repeated every 5 s, with the
               same source port reused across cycles.
  Master log:  [probe] 127.0.0.1:8081 -> 200, repeated every 5 s.
  Smoke test:  a JSON object with id "chatcmpl-..." and one choice.

MULTI-DEVICE (DO NOT DO THIS YET)
  The --workers flag accepts a comma-separated list, but section 5 item M13
  explains why a chain of two or more workers produces a technically
  successful 200 with semantically wrong results. Wait for v3.x.

STOPPING
  Ctrl-C in each terminal. uvicorn honours timeout_graceful_shutdown=10 and
  will cancel work that is blocked in a C extension after 10 seconds.

TEARDOWN AND REVERT
  git tag -l                      # see available versions
  git checkout v2.9               # revert code to a known-good state
  ./build_dhlpe.sh                # idempotent rebuild of certificates
  To revert only the certificates:
  ./make_certs.sh                 # regenerates any certificate whose SAN,
                                  # EKU, or keyUsage no longer matches

4. SAFETY FENCING -- IMPLEMENTED
---------------------------------
Each item below is present in the current code and has been verified by
reading the source or by observing the behaviour in a live run.

S1  Mutual TLS on both inbound sockets.  ssl.CERT_REQUIRED is set on the
    worker and on the master. A client without a certificate signed by
    certs/ca.crt cannot complete the handshake, so it never reaches a route.
    TLS 1.3 makes forward secrecy mandatory via ephemeral Diffie-Hellman.

S2  CA keyUsage and leaf extensions.  The CA carries
    keyUsage=critical,keyCertSign,cRLSign and basicConstraints=critical,CA:TRUE.
    Every leaf carries Subject Alternative Names, extendedKeyUsage
    serverAuth+clientAuth, subjectKeyIdentifier and authorityKeyIdentifier.
    This is required by RFC 5280 section 4.2.1.9 and enforced by Python 3.13's
    VERIFY_X509_STRICT default.

S3  Idempotent certificate regeneration.  make_certs.sh inspects the existing
    CA and leaves, and regenerates only what is non-compliant. A second run
    is a no-op. This is what makes the certificate layer revertible: you can
    always return to a compliant state without deleting anything.

S4  Constant-time HMAC-SHA256.  hmac.compare_digest is used, never == or
    memcmp. This removes the timing side channel that a byte-wise comparison
    would expose.

S5  Ed25519 verification path.  Available for per-node attribution, with
    32-byte public keys verified through the cryptography library. Not yet
    wired to a key registry (see M4).

S6  Binary framing with checksum.  A length mismatch, a bad magic value, or
    a SHA-256 mismatch raises ValueError before any deserialisation. This
    prevents both truncation attacks and the "oversized message length"
    crash class that affected the llama.cpp RPC server.

S7  Quantisation block-alignment and byte-length validation.  Unknown quant
    types are rejected, ne[0] must be a multiple of the block size, and the
    payload length must equal product(shape) times 4 for float32. This is
    the direct mitigation for CVE-2026-86317.

S8  Bounded KV cache.  DHLPE_MAX_KV_ELEMENTS caps resident KV memory. A
    request that would exceed it receives 507 instead of triggering an OOM
    kill.

S9  Bounded token budget.  MAX_TOKENS_PER_REQUEST on the worker and
    MAX_TOKENS_HARD_CAP on the master bound the denial-of-wallet surface
    described by OWASP LLM10:2025.

S10 Sliding-window rate limit on both inbound routes.  Requests are counted
    per key in a one-second window. This is advisory, not authoritative (see
    M6), but it stops accidental floods.

S11 Keepalive alignment.  Server 30 s, client 20 s. The client always
    recycles an idle connection before the server closes it. This is visible
    in the logs as a stable source port across probe cycles.

S12 Graceful shutdown bound.  timeout_graceful_shutdown=10 prevents a
    worker from hanging forever on a request blocked in a C extension.

S13 Lifespan-managed resources.  The httpx client and the probe task are
    created and cancelled in an asynccontextmanager, not in deprecated
    on_event hooks. The task reference is retained, so it cannot be
    garbage-collected mid-flight.

S14 Structured failure surface.  The probe prints [probe] <addr> -> <code>
    or [probe] <addr> FAILED: <exception> to stderr, and the last error is
    included in the 503 detail. This is what makes the system diagnosable.

S15 Reproducible scripts.  No sed, no set -e, no exit 1, no 2>/dev/null,
    no rm -rf. Every script is safe to re-run.

5. SAFETY FENCING -- REQUIRED BUT NOT YET IMPLEMENTED
------------------------------------------------------
These are real gaps. They are numbered so that commits and issues can refer
to them.

M1  Peer identity is not verified.  DHLPE_SKIP_HOSTNAME defaults to 1, and
    check_hostname is set to False. The chain is validated to the CA, but
    the peer name is not. Any certificate signed by the CA can impersonate
    any node. FIX: issue leaf certificates with the device IP in the SAN,
    set DHLPE_SKIP_HOSTNAME=0 by default, and fail closed if the name does
    not match.

M2  One credential, three roles.  master.crt is simultaneously the master's
    server certificate, the master's client certificate to workers, and the
    curl client certificate. FIX: separate server, client, and operator
    certificates, and issue one client certificate per node.

M3  HMAC key equals the API bearer token.  Both are --secret. Any API
    consumer therefore knows the cluster MAC key and can forge frames to
    /compute-slice directly. FIX: DHLPE_API_TOKEN and DHLPE_CLUSTER_HMAC_KEY
    must be distinct secrets, and the worker must reject a frame whose MAC
    was produced with the API token.

M4  Ed25519 is not wired.  No public keys are registered, so every request
    falls through to HMAC. FIX: load a node_id -> public key map at startup,
    reject HMAC when a node has a registered key, and rotate keys per node.

M5  No replay protection.  The MAC covers the body only. FIX: add a nonce
    and an issued-at timestamp to the signed payload, keep a bounded nonce
    cache (or a monotonic counter per session), and reject anything outside
    a 30-second window.

M6  Rate-limit key is forgeable.  X-Client-Ip is client-supplied. FIX: key
    the limiter on the peer certificate subject or SPIFFE ID, which uvicorn
    exposes on the transport, and rate-limit /heartbeat as well.

M7  Unbounded client_history.  One entry per key, forever. FIX: an LRU with
    a size cap, evicted on the same timer as the rate window.

M8  Unbounded request body.  await request.body() has no Content-Length cap.
    FIX: reject Content-Length above a configured maximum before reading,
    and enforce the same cap while streaming.

M9  No KV eviction or persistence.  Once the cap is reached, new sessions
    get 507 forever, and a crash loses every in-flight generation. FIX: an
    OrderedDict with TTL and LRU eviction, plus a SQLite WAL checkpoint per
    generation step (see section 6).

M10 No circuit breaker, no backoff, no bulkhead.  worker_health is a bool.
    FIX: a failure counter with hysteresis, a half-open probe, exponential
    backoff with full jitter, and a per-worker semaphore.

M11 No process isolation.  The worker runs as the same user with no seccomp,
    no Landlock, no user namespace, and no RLIMIT. FIX: run each worker in a
    systemd unit with SystemCallFilter, RestrictAddressFamilies, MemoryMax,
    and a dedicated UID.

M12 No supply-chain controls.  requirements.txt uses >= with no hashes and
    no lock file; msgpack-numpy is dormant. FIX: pin with hashes, produce a
    CycloneDX SBOM, sign with cosign, and publish SLSA provenance from CI.

M13 Multi-worker frame loses routing metadata.  The worker rebuilds the
    outbound frame without layer_idx or max_tokens. FIX: echo the full
    routing envelope, and add a per-hop hop_count with a maximum.

M14 No observability or audit trail.  print to stderr only; the prompt is
    echoed in the response body. FIX: OpenTelemetry spans with a trace ID
    propagated in a header, structured JSON logs, and redaction of prompt
    and completion fields before emission.

M15 No tests.  There is no pytest suite and no CI. The very defects that
    v2.4 through v2.9 fixed would regress silently. FIX: unit tests for
    partitioner invariants, security_fence block alignment, and the
    protocol round-trip; a live integration test for the mTLS path.

M16 No license file.  Without a LICENSE the repository is not open source
    in the legal sense, whatever the description says. FIX: add SPDX-
    identified LICENSE and a NOTICE file.

M17 No SECURITY.md.  There is no vulnerability disclosure policy and no
    threat model document. FIX: add SECURITY.md with a contact, a scope, and
    a 90-day disclosure window.

M18 Secrets on the command line.  --secret is visible in ps and in shell
    history. FIX: read from a file descriptor or from systemd credentials.

6. RECOVERABLE AND REVERTIBLE STATES
------------------------------------
The brief asks for recoverable and revertible states. The current code has
one of the two. It is fully revertible at the repository level, and it is
not recoverable at the request level.

REVERTIBLE (implemented)
  Every version is a git commit, the build is idempotent, and the
  certificate generator is self-healing. "git checkout v2.9 && ./build_dhlpe.sh"
  returns a known-good state. This is a genuine property, not a claim.

RECOVERABLE (not implemented)
  A crash loses all in-flight KV state. There is no checkpoint, no
  write-ahead log, and no idempotency key. The design below is the minimum
  that would make the claim true.

R1  Idempotency key.  The client sends Idempotency-Key. The master persists
    (key -> session_id, final_frame_digest) in SQLite WAL before returning.
    A retry with the same key returns the cached result and does not
    recompute. This is the standard exactly-once-at-the-edge pattern.

R2  Per-step checkpoint.  After each layer slice, the worker writes
    (session_id, layer_idx, step, kv_digest) to the same WAL with
    synchronous=FULL. On restart, the worker replays from the last complete
    checkpoint. SQLite WAL is chosen because it reduces the commit cost from
    four fsyncs to one and survives power loss at synchronous=FULL.

R3  Crash-only startup.  There is no "clean shutdown" path. Every start is a
    recovery. This is the crash-only design of Candea and Fox: a component
    that can only be stopped by crashing it, and can only be started by
    recovering it, is easier to reason about and recovers faster.

R4  Saga with compensation.  The pipeline is a saga. If stage k fails, the
    master issues COMPENSATE to stages 1..k-1 to release their KV slices,
    then returns a typed error. There are no external writes, so compensation
    is pure memory release -- but the pattern still matters, because it makes
    the failure path explicit and testable.

R5  Circuit breaker with half-open probe.  After N consecutive failures,
    the breaker opens for a backoff window, then allows a single half-open
    probe. On success it closes; on failure it re-opens with jitter. This
    replaces the current fixed 5-second retry, which is a retry storm.

R6  Bulkhead.  A per-worker semaphore bounds concurrent requests. A slow
    worker cannot starve the event loop for every other worker.

R7  Bounded queue with explicit shedding.  When the queue is full, return
    429 with Retry-After rather than accepting unbounded work.

R8  Configuration rollback.  A versioned config file plus a last-known-good
    copy. On startup, if the config fails schema validation, fall back to
    the last-known-good and log the fact.

7. THREAT MODEL AND MITIGATION MATRIX
--------------------------------------
Each row names the threat, the mechanism, and whether the mitigation is
implemented (I), partial (P), or missing (M).

T1  Unauthenticated RPC injection.        I  mTLS + CERT_REQUIRED (S1).
T2  Arbitrary code execution via RPC.     P  No code path executes remote
                                             input, but no sandbox (M11).
T3  Quantisation-triggered abort (CVE).   I  Block alignment + length check
                                             (S7).
T4  Activation inversion / prompt leak.   P  Channel is encrypted, but the
                                             worker sees plaintext
                                             activations. Split-learning
                                             inversion is a published class
                                             of attack; encrypting the
                                             channel does not prevent a
                                             malicious worker from
                                             reconstructing the prompt.
T5  Weight theft in transit.              I  mTLS (S1).
T6  Compromised worker impersonates peer. M  check_hostname disabled (M1)
                                             and shared cert (M2).
T7  API consumer forges cluster frame.    M  Shared secret (M3).
T8  Replay of a captured frame.           M  No nonce/timestamp (M5).
T9  Rate-limit bypass.                    M  Forgeable header (M6).
T10 Denial of wallet.                     P  Token caps and rate limit, but
                                             no per-identity quota and no
                                             global budget.
T11 Memory exhaustion via body size.      M  No Content-Length cap (M8).
T12 KV exhaustion via session flood.      M  No eviction (M9).
T13 Stolen key valid for a decade.        M  No rotation, no revocation (M9
                                             in section 5).
T14 Supply-chain compromise.              M  No hashes, no SBOM, no signing
                                             (M12).
T15 Silent regression.                    M  No tests, no CI (M15).
T16 Unlogged events.                      M  No structured audit trail (M14).

8. KNOWN FAILURE MODES AND DIAGNOSTICS
---------------------------------------
F1  "no healthy workers".  The probe has not succeeded. Watch the master
    stderr for [probe] FAILED lines, then run:
      python diag_probe.py --workers 127.0.0.1:8081
    The most common causes are a CA without keyUsage (run ./make_certs.sh),
    a SAN mismatch (run ./preflight.sh), or a client certificate that httpx
    did not load (the v2.6 fix).

F2  "worker returned 500".  Watch the worker stderr. A UnicodeDecodeError in
    fastapi/encoders.py means a route returned bare bytes; wrap it in
    Response(media_type="application/octet-stream"). A reshape ValueError
    means the tensor length check was bypassed; check S7.

F3  "worker returned 502".  The worker answered, but with a non-200 status.
    Read the worker log for the status and the detail.

F4  Intermittent RemoteProtocolError.  This is the keepalive race. Confirm
    that timeout_keep_alive=30 and keepalive_expiry=20.0 are both present.
    If the race persists, the client is not recycling before the server
    closes.

F5  "address already in use".  An older process still holds the port. Run
    ./preflight.sh and kill the PID it prints.

F6  Permission denied on certs.  The key files must be mode 0600. make_certs.sh
    creates them with the process umask; check with ls -l.

F7  "fatal error in commit_refs" on git push.  This is a server-side
    reference-update failure, not a local history problem. The pack upload
    succeeds; only the ref write fails. Do NOT force-push and do NOT delete
    the repository. Retry later, try a new branch name
    (git push origin HEAD:refs/heads/<new>), and if it persists open a
    support ticket citing the commit SHA, the timestamp, and GitHub
    Community Discussions #212107, #212116, #212106, #212148.

9. OPERATIONAL RUNBOOK
----------------------
ROTATE A NODE KEY
  1. Stop the node.
  2. Delete only that node's .key and .crt (not the CA).
  3. Run ./make_certs.sh. It regenerates the missing leaf and reuses the CA.
  4. Restart the node.
  Because the CA is preserved, every other node continues to trust the new
  certificate without reconfiguration.

ROTATE THE CA (BREAKING)
  1. Move certs/ aside (do not delete; keep it for rollback).
  2. Run ./make_certs.sh to mint a new CA and leaves.
  3. Distribute the new ca.crt to every node.
  4. Restart all nodes.
  Rollback is "move the old certs directory back".

RECOVER FROM A LOST WORKER
  1. The master's probe marks it unhealthy within 5 seconds.
  2. Requests that were in flight receive 503 with the last probe error.
  3. Restart the worker; the probe recovers it automatically.
  Note: in-flight generations are lost. This is the gap that section 6 R2
  is designed to close.

ROLL BACK A BAD DEPLOY
  1. git log --oneline to find the last known-good commit.
  2. git checkout <commit>.
  3. ./build_dhlpe.sh (idempotent).
  4. Restart both processes.
  Certificates do not need to be regenerated unless the CA changed.

10. COMPLIANCE MAPPING
----------------------
OWASP LLM Top 10 2025
  LLM01 Prompt Injection        -- no schema validation yet (M15 in the
                                   original list; add a Pydantic request
                                   model with a role whitelist and a max
                                   prompt length).
  LLM05 Improper Output Handling -- no output validation yet.
  LLM10 Unbounded Consumption    -- token caps (S9) and rate limit (S10)
                                   are implemented; per-identity quota and
                                   global budget are not.

OWASP ASVS 5.0
  V1 Encoding and Sanitization   -- partial (no Pydantic model).
  V6 Authentication              -- mTLS (S1), but shared credential (M2).
  V9 Self-Contained Tokens       -- the bearer token is compared in constant
                                   time; it is not a JWT and has no expiry.
  V11 Cryptography               -- HMAC-SHA256 and Ed25519 are correct;
                                   key management and rotation are missing.
  V12 Secure Communication       -- TLS 1.3 with mTLS; hostname verification
                                   disabled (M1).
  V14 Data Protection            -- no PII redaction (M14).

NIST SP 800-207 Zero Trust
  The design moves in the right direction (no implicit trust between master
  and worker), but continuous verification is weakened by check_hostname
  being off and by one credential serving three roles. Both are M1/M2.

NIST AI RMF 1.0 and AI 600-1
  Risk identification and measurement are addressed by the threat matrix.
  Governance (logging, incident response, disclosure) is not: M14 and M17.

EU AI Act Article 12
  Automatic logging over the lifetime of the system is required for
  high-risk systems. The current stderr prints are not tamper-resistant and
  are not retained. M14.

ISO/IEC 42001:2023
  An AI management system needs documented controls and evidence. This
  README is a starting point; a control register and an audit log are not
  present.

11. SUPPLY CHAIN AND REPRODUCIBILITY
-------------------------------------
Current state: requirements.txt uses >= with no hashes and no lock file.
msgpack-numpy has not been released since 2022 and its deserialised arrays
are read-only, which is why the worker calls .copy() before mutating.

Required:
  - Pin every dependency to an exact version with a SHA-256 hash.
  - Produce a CycloneDX or SPDX SBOM on every release.
  - Sign the SBOM and the release artefacts with cosign, and publish SLSA
    provenance from a hosted CI runner.
  - Add Dependabot or Renovate, and a CodeQL workflow.
  - Add a LICENSE (SPDX identifier) and a SECURITY.md.

12. ROADMAP TO v3.x
--------------------
v3.0  This document. Add LICENSE, SECURITY.md, tests, CI.
v3.1  Wire the partitioner; carry layer_idx and max_tokens across hops;
      make multi-worker correct.
v3.2  Split identities (M2), separate API token from HMAC key (M3), enable
      hostname verification by default (M1).
v3.3  Replay protection (M5), nonce cache, timestamp window.
v3.4  Short-lived certificates and rotation (M9), or SPIFFE SVIDs.
v3.5  Circuit breaker, backoff, bulkhead, bounded queue (M10, R5-R7).
v3.6  SQLite WAL checkpoint and idempotency key (R1-R3).
v3.7  seccomp/Landlock/systemd hardening (M11).
v3.8  OpenTelemetry, trace IDs, PII redaction (M14).
v3.9  SBOM, cosign, SLSA provenance (M12).

13. REFERENCES
---------------
Standards
  RFC 2104  HMAC: Keyed-Hashing for Message Authentication.
            https://datatracker.ietf.org/doc/html/rfc2104
  RFC 5280  Internet X.509 Public Key Infrastructure, section 4.2.1.9
            (Basic Constraints) and section 4.2.1.12 (Extended Key Usage).
            https://datatracker.ietf.org/doc/html/rfc5280
  RFC 6125  Representation and Verification of Domain-Based Application
            Service Identity, section 6.4.4.
            https://datatracker.ietf.org/doc/html/rfc6125
  RFC 8032  Edwards-Curve Digital Signature Algorithm (EdDSA).
            https://datatracker.ietf.org/doc/html/rfc8032
  RFC 8446  The Transport Layer Security (TLS) Protocol Version 1.3.
            https://datatracker.ietf.org/doc/html/rfc8446
  CA/B Forum Ballot SC-12, Deprecation of Internal Names.
            https://cabforum.org/2016/01/14/ballot-sc12-deprecate-internal-names/

Security guidance
  OWASP Top 10 for LLM Applications 2025.
            https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  OWASP Application Security Verification Standard 5.0.
            https://asvs.dev/
  NIST SP 800-207, Zero Trust Architecture.
            https://csrc.nist.gov/pubs/sp/800/207/final
  NIST AI 600-1, Generative AI Profile (companion to AI RMF 1.0).
            https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
  ISO/IEC 42001:2023, AI management systems.
            https://www.iso.org/standard/81230.html
  EU AI Act, Article 12 (Record-keeping).
            https://artificialintelligenceact.eu/article/12/

Systems and distributed-systems literature
  Narayanan, D. et al. Efficient Large-Scale Language Model Training on GPU
  Clusters Using Megatron-LM. arXiv:2104.04473.
            https://arxiv.org/abs/2104.04473
  Candea, G. and Fox, A. Crash-Only Software. HotOS IX, 2003.
            https://www.usenix.org/legacy/events/hotos03/tech/full_papers/candea/candea.pdf
  SQLite Write-Ahead Logging.
            https://www.sqlite.org/wal.html

Implementation references
  llama.cpp RPC discussion #9446.
            https://github.com/ggml-org/llama.cpp/discussions/9446
  CVE-2026-86317, llama.cpp RPC server unauthenticated assertion.
            https://nvd.nist.gov/vuln/detail/CVE-2026-86317
  Distributed Llama (b4rtaz).
            https://github.com/b4rtaz/distributed-llama
  msgpack-numpy (lebedov).
            https://github.com/lebedov/msgpack-numpy
  httpx client-side certificates.
            https://www.python-httpx.org/advanced/ssl/#client-side-certificates
  httpx resource limits.
            https://www.python-httpx.org/advanced/resource-limits/
  uvicorn HTTP settings (timeout_keep_alive).
            https://www.uvicorn.org/settings/#http
  FastAPI custom response.
            https://fastapi.tiangolo.com/advanced/custom-response/
  FastAPI lifespan.
            https://fastapi.tiangolo.com/advanced/events/
  Python ssl.VERIFY_X509_STRICT.
            https://docs.python.org/3/library/ssl.html#ssl.VERIFY_X509_STRICT
  hmac.compare_digest.
            https://docs.python.org/3/library/hmac.html#hmac.compare_digest
  SPIFFE/SPIRE workload identity.
            https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
  Sigstore cosign and SLSA.
            https://docs.sigstore.dev/cosign/overview/
            https://slsa.dev/spec/v1.2/

14. LICENSE AND CREDITS
------------------------
This project currently has no LICENSE file. That must be corrected before
any redistribution; without it, the default is all rights reserved.

Credit is due to the upstream projects whose ideas and code this harness
builds on: b4rtaz for Distributed Llama, the ggml-org and llama.cpp
contributors for the RPC backend and the quantisation block layout, lebedov
for msgpack-numpy, laurentS for SlowAPI, the encode/uvicorn maintainers for
the keepalive semantics, the FastAPI maintainers for the lifespan and
custom-response APIs, and the IETF, NIST, OWASP, and CA/B Forum working
groups for the standards that make the fencing auditable.
