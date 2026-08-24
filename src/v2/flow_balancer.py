import zlib
from dataclasses import dataclass

@dataclass(frozen=True)
class FlowKey:
    """
    Identifies a network flow using the five-tuple.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def canonical(self) -> tuple:
        """
        Return a direction-independent representation of the flow.
        """
        forward = (
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
        )
        reverse = (
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
        )

        endpoints = min(forward, reverse)

        return (
            endpoints[0],
            endpoints[1],
            endpoints[2],
            endpoints[3],
            self.protocol,
        )

class FlowBalancer:
    """
    Assigns network flows to workers using five-tuple hashing.
    """
    def __init__(self, worker_count: int):
        if worker_count <= 0:
            raise ValueError("worker_count must be greater than zero")
        self.worker_count = worker_count

    def get_worker(self, flow: FlowKey) -> int:
        """
        Return the worker ID responsible for this flow.

        Uses crc32 rather than the built-in hash(). Python randomises
        string hashing per process (PYTHONHASHSEED), so hash() would
        send the same flow to a different worker on every run and
        destroy the flow affinity this class exists to provide.
        """

        flow_key = "|".join(
            str(part)
            for part in flow.canonical()
        ).encode("utf-8")

        return zlib.crc32(flow_key) % self.worker_count