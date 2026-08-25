from typing import Any
from src.packet_parser import PacketParser
from src.connection_tracker import ConnectionTracker
from src.sni_extractor import SNIExtractor
from src.http_host_extractor import HTTPHostExtractor

class DPIProcessor:
    """
    Adapter between the V2 worker system and the
    existing V1 DPI processing pipeline.
    """

    def __init__(self,blocked_ips=None,blocked_apps=None,blocked_domains=None,):

        # V1 components reused by the V2 processing pipeline.
        self.parser = PacketParser()
        self.connection_tracker = ConnectionTracker(
            blocked_ips=blocked_ips,
            blocked_apps=blocked_apps,
            blocked_domains=blocked_domains,
        )
        self.sni_extractor = SNIExtractor()
        self.http_host_extractor = HTTPHostExtractor()

        # Count packets successfully processed by this processor.
        self.processed_packets = 0

    def process(self, packet: Any) -> dict:
        """
        Parse a packet, track its flow, and extract TLS SNI.
        """

        # Convert the raw Scapy packet into structured packet data.
        parsed_packet = self.parser.parse(packet)

        # Build the five-tuple used to identify the network flow.
        five_tuple = self.connection_tracker.create_five_tuple(parsed_packet)

        # Get the existing flow or create a new one.
        flow = self.connection_tracker.get_or_create_flow(five_tuple)

        payload = parsed_packet.get("payload", b"")
        sni = self.sni_extractor.extract(payload)
        http_host = None

        if not sni:
            http_host = self.http_host_extractor.extract(payload)
        domain = sni or http_host

        if domain:
            flow.sni = domain
            flow.app_type = (
                self.connection_tracker.rule_manager.classify_domain(domain)
            )
            self.connection_tracker.apply_blocking_rules(flow)

        self.processed_packets += 1

        return {
            "packet": parsed_packet,
            "raw_packet": packet,
            "flow": flow,
            "sni": sni,
            "http_host": http_host,
            "decision": "DROP" if flow.blocked else "FORWARD",
        }

    @property
    def packet_count(self) -> int:
        """Return the number of processed packets."""

        return self.processed_packets