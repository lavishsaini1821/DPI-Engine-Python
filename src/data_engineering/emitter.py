"""
Convert DPI pipeline output into NetworkEvent objects.

Takes the tuple returned by DPIEngine.process_packets() and
walks parsed_packets + decisions + connection_tracker.flows
to produce one event per packet. Pure transformation,
no I/O, no side effects.
"""
from typing import List

from src.data_engineering.events import NetworkEvent


class NetworkEventEmitter:
    """Builds NetworkEvent objects from DPI engine output."""

    def __init__(self, parsed_packets, decisions, connection_tracker):
        self._parsed_packets = parsed_packets
        self._decisions = decisions
        # Index flows so each packet can be enriched with its flow's
        # SNI, application, and blocked state. FiveTuple is a frozen
        # dataclass, so it hashes like a tuple of its fields.
        self._flow_by_key = {
            flow.five_tuple: flow
            for flow in connection_tracker.flows.values()
        }

    def emit_all(self) -> List[NetworkEvent]:
        events = []
        for packet, decision in zip(self._parsed_packets, self._decisions):
            flow = self._lookup_flow(packet)
            events.append(self._build_event(packet, decision, flow))
        return events

    def _lookup_flow(self, packet):
        """Return the tracked flow for this packet, or None."""
        from src.types import FiveTuple
        try:
            key = FiveTuple(
                src_ip=packet.get("src_ip", ""),
                dst_ip=packet.get("dst_ip", ""),
                src_port=packet.get("src_port", 0),
                dst_port=packet.get("dst_port", 0),
                protocol=packet.get("protocol", ""),
            )
        except Exception:
            return None
        return self._flow_by_key.get(key)

    def _build_event(self, packet, decision, flow):
        """Build one NetworkEvent from a packet, its decision, and its flow."""
        return NetworkEvent(
            src_ip=packet.get("src_ip", ""),
            dst_ip=packet.get("dst_ip", ""),
            src_port=packet.get("src_port", 0),
            dst_port=packet.get("dst_port", 0),
            protocol=packet.get("protocol", ""),
            packet_length=packet.get("packet_length", 0),
            sni=flow.sni if flow else None,
            http_host=None,  # V1 dict does not surface HTTP fields
            http_method=None,
            http_path=None,
            user_agent=None,
            application=(
                flow.app_type.value if flow and flow.app_type else "UNKNOWN"
            ),
            decision=decision,
            blocked=bool(flow.blocked) if flow else False,
            flow_packet_count=flow.packet_count if flow else 0,
        )
