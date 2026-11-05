"""
security_fence.py — Cryptographic fencing, replay protection, tensor validation.

v3.1 adds nonce + timestamp replay protection. HMAC alone is not enough:
a captured frame verifies forever. OWASP: "include timestamps or nonces in
messages and reject duplicates". RFC 2104 defines the MAC; freshness is the
application's job.

Citations:
  [1] RFC 2104 HMAC: https://datatracker.ietf.org/doc/html/rfc2104
  [2] RFC 8032 Ed25519: https://datatracker.ietf.org/doc/html/rfc8032
  [4] llama.cpp RPC: https://github.com/ggml-org/llama.cpp/discussions/9446
  [14] OWASP CheatSheetSeries (replay):
       https://github.com/OWASP/CheatSheetSeries
  [18] hmac.compare_digest:
       https://docs.python.org/3/library/hmac.html#hmac.compare_digest
"""

import hashlib
import hmac as _hmac
import time
from collections import OrderedDict
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SecurityFence:
    QUANT_BLOCK_SIZES = {
        0: 1, 1: 1, 2: 32, 3: 32, 6: 32, 7: 32, 8: 32, 9: 32,
        10: 256, 11: 256, 12: 256, 13: 256, 14: 256, 15: 256,
        16: 256, 17: 256, 18: 256, 19: 32, 20: 32, 21: 256,
        22: 256, 23: 256, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1,
        29: 256, 30: 1, 34: 256, 35: 256,
    }

    def __init__(
        self,
        shared_secret: str,
        ed25519_public_keys: Optional[Dict[str, bytes]] = None,
        rate_limit_window: float = 1.0,
        max_requests: int = 30,
        nonce_ttl: int = 30,
        max_nonces: int = 10000,
    ):
        self.shared_secret = shared_secret.encode("utf-8")
        self.ed25519_public_keys = ed25519_public_keys or {}
        self.rate_limit_window = rate_limit_window
        self.max_requests = max_requests
        self.nonce_ttl = nonce_ttl
        self.max_nonces = max_nonces
        self.client_history: Dict[str, list] = {}
        self.nonce_cache: "OrderedDict[str, float]" = OrderedDict()

    # -- replay protection ------------------------------------------------
    def _evict_nonces(self) -> None:
        now = time.time()
        while self.nonce_cache:
            oldest, ts = next(iter(self.nonce_cache.items()))
            if now - ts > self.nonce_ttl:
                self.nonce_cache.popitem(last=False)
            else:
                break

    def check_nonce(self, nonce: str, timestamp: int) -> bool:
        """
        Accept a nonce exactly once, inside a +/- nonce_ttl window.

        The nonce must be inside the HMAC-signed body, so an attacker cannot
        alter it without breaking the MAC. This function then enforces
        freshness and single use. Eviction is O(1) amortised.
        """
        if not nonce or not isinstance(nonce, str) or len(nonce) > 128:
            return False
        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return False
        now = int(time.time())
        if abs(now - ts) > self.nonce_ttl:
            return False
        self._evict_nonces()
        if nonce in self.nonce_cache:
            return False
        self.nonce_cache[nonce] = now
        if len(self.nonce_cache) > self.max_nonces:
            self.nonce_cache.popitem(last=False)
        return True

    # -- authentication ---------------------------------------------------
    def verify_ed25519(self, node_id: str, payload: bytes, signature: bytes) -> bool:
        pub = self.ed25519_public_keys.get(node_id)
        if not pub or len(pub) != 32:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, payload)
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify_hmac_legacy(self, payload: bytes, signature_hex: str) -> bool:
        computed = _hmac.new(
            self.shared_secret, payload, hashlib.sha256
        ).hexdigest()
        return _hmac.compare_digest(computed, signature_hex)

    # -- rate limiting ----------------------------------------------------
    def check_rate_limit(self, key: str) -> bool:
        now = time.time()
        history = [
            t for t in self.client_history.get(key, [])
            if now - t < self.rate_limit_window
        ]
        if len(history) >= self.max_requests:
            return False
        history.append(now)
        self.client_history[key] = history
        # Bound the dict so it cannot grow one entry per key forever.
        if len(self.client_history) > 4096:
            for k in list(self.client_history)[:1024]:
                del self.client_history[k]
        return True

    @classmethod
    def validate_tensor_block_alignment(cls, tensor_shape: list, quant_type: int = 0) -> bool:
        if not isinstance(tensor_shape, list) or not tensor_shape:
            return False
        block_size = cls.QUANT_BLOCK_SIZES.get(quant_type)
        if block_size is None:
            return False
        ne0 = tensor_shape[0]
        if not isinstance(ne0, int) or ne0 <= 0 or ne0 % block_size != 0:
            return False
        total = 1
        for dim in tensor_shape:
            if not isinstance(dim, int) or dim <= 0 or dim > 16384:
                return False
            total *= dim
            if total > 2_000_000_000:
                return False
        return True
