from src.packet_parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.connection_tracker import ConnectionTracker
from src.sni_extractor import SNIExtractor
class DPIEngine:
    """
    Coordinates packet parsing and traffic analysis, 
    flow tracking and blocking decision.
    """

    def __init__(self):
        # Create the packet parser used to convert raw packets
        # into structured packet information.
        self.parser = PacketParser()

        # Track packets belonging to the same network flow.
        self.connection_tracker = ConnectionTracker()

        # Create the analyzer used to inspect parsed packets
        # and collect traffic statistics.
        self.analyzer = PacketAnalyzer(
            self.connection_tracker
        )

        # Extract SNI domains from TLS ClientHello payloads.
        self.sni_extractor = SNIExtractor()

    def process_packets(self, packets):
        """
        Parse, track and analyze a collection of packets.
        """
        # Store the structured information of every packet.
        parsed_packets = []

        # Store the FORWARD or DROP decision for every packet.
        decisions = []

        # Store packets that are allowed to pass.
        forwarded_packets = []

        # Process packets one by one through the parser.
        for packet in packets:
            parsed_packet = self.parser.parse(packet)
            parsed_packets.append(parsed_packet)

            five_tuple = self.connection_tracker.create_five_tuple(parsed_packet)

            # Skip packets that carry no usable IP information.
            if five_tuple is None:
                continue

            # Extract the application payload from the parsed packet.
            payload = parsed_packet.get("payload", b"")

            # Try to extract the SNI from a TLS ClientHello payload.
            sni = self.sni_extractor.extract(payload)

            # Get the existing flow or create a new flow.
            # Pass the SNI so the flow can be classified and blocked.
            flow = self.connection_tracker.get_or_create_flow(five_tuple,sni=sni)

            # Decide whether the current flow should be
            # forwarded or dropped.
            if flow.blocked:
                decision = "DROP"
            else:
                decision = "FORWARD"

            # Store the decision for this processed packet.
            decisions.append(decision)

            # Keep only packets that are allowed to pass.
            if decision == "FORWARD":
                forwarded_packets.append(packet)

        # Analyze all packets after parsing is complete.
        protocol_statistics = self.analyzer.analyze(parsed_packets)
        return (parsed_packets, protocol_statistics, decisions,forwarded_packets)