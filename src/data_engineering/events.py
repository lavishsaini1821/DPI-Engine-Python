"""
Structured event produced by the DPI pipeline.

One NetworkEvent = one processed packet.
All fields are derived from existing DPI output;
no new parsing or sniffing happens here.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NetworkEvent:
    # Layer 3/4
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_length: int

    # Layer 7 (None for non-HTTP/non-TLS packets)
    sni: Optional[str]
    http_host: Optional[str]
    http_method: Optional[str]
    http_path: Optional[str]
    user_agent: Optional[str]

    # Classification + enforcement
    application: str        # e.g. "GOOGLE", "UNKNOWN"
    decision: str           # "FORWARD" or "DROP"
    blocked: bool
    flow_packet_count: int
