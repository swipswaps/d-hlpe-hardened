"""
partitioner.py — RAM-proportional layer partitioning.

Citations:
  [5]  https://github.com/zhengpeirong/_distributed-llama
  [11] https://arxiv.org/abs/2104.04473
"""

from typing import Dict, List


class LayerPartitioner:
    def __init__(self, total_layers: int, kv_heads: int):
        if total_layers <= 0 or kv_heads <= 0:
            raise ValueError("total_layers and kv_heads must be positive")
        self.total_layers = total_layers
        self.kv_heads = kv_heads

    def validate_topology(self, node_rams: List[int]) -> bool:
        n = len(node_rams)
        if n & (n - 1) != 0:      # must be power of 2 [5]
            return False
        if n > self.kv_heads:     # node count <= KV heads [5]
            return False
        return True

    def partition(self, node_rams: List[int]) -> List[Dict]:
        if not self.validate_topology(node_rams):
            raise ValueError("topology violates 2^n or KV-head constraint")
        total_ram = sum(node_rams)
        if total_ram == 0:
            raise ValueError("total RAM must be > 0")
        allocations, cursor = [], 0
        for idx, ram in enumerate(node_rams):
            if idx == len(node_rams) - 1:
                end = self.total_layers
            else:
                share = ram / total_ram
                count = max(1, round(self.total_layers * share))
                end = min(cursor + count, self.total_layers)
            allocations.append(
                {"start_layer": cursor, "end_layer": end, "ram_bytes": ram}
            )
            cursor = end
        for a in allocations:
            if a["end_layer"] <= a["start_layer"]:
                raise ValueError("zero-layer allocation")
        return allocations
