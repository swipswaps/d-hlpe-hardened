"""
protocol.py — Binary tensor framing with SHA-256 checksums.

Citations:
  [4]  https://github.com/ggml-org/llama.cpp/discussions/9446
  [7]  https://datasea.cn (2026-09-21, 5.67x vs JSON)
  [16] https://github.com/lebedov/msgpack-numpy
  [18] https://docs.python.org/3/library/hmac.html#hmac.compare_digest
"""

import hashlib
import hmac
import struct
from typing import Any, Tuple

import msgpack
import numpy as np

try:
    import msgpack_numpy as m
    m.patch()  # register ndarray + dtype handlers [16]
except ImportError as exc:
    raise ImportError(
        "msgpack-numpy is required for ndarray serialization. "
        "Install with: pip install msgpack-numpy  (see requirements.txt)"
    ) from exc

MAGIC = b"DHLP"
CMD_COMPUTE = 0x01
CMD_HEARTBEAT = 0x02
CMD_SHUTDOWN = 0x03


def encode_frame(cmd: int, payload: Any) -> bytes:
    body = msgpack.packb(payload, use_bin_type=True)
    digest = hashlib.sha256(body).digest()
    header = MAGIC + struct.pack(">BQ", cmd, len(body)) + digest
    return header + body


def decode_frame(data: bytes) -> Tuple[int, Any]:
    if len(data) < 45:
        raise ValueError("frame too short")
    if data[:4] != MAGIC:
        raise ValueError("bad magic")
    cmd, payload_len = struct.unpack(">BQ", data[4:13])
    expected = data[13:45]
    body = data[45:]
    if len(body) != payload_len:
        raise ValueError("length mismatch")
    actual = hashlib.sha256(body).digest()
    if not hmac.compare_digest(actual, expected):  # [18]
        raise ValueError("checksum mismatch")
    return cmd, msgpack.unpackb(body, raw=False)


def tensor_to_msgpack(tensor: np.ndarray, quant_type: int = 0) -> dict:
    return {
        "shape": list(tensor.shape),
        "dtype": str(tensor.dtype),
        "quant_type": quant_type,
        "data": tensor.tobytes(),
    }


def msgpack_to_tensor(obj: dict) -> np.ndarray:
    dtype = np.dtype(obj["dtype"])
    return np.frombuffer(obj["data"], dtype=dtype).reshape(obj["shape"])
