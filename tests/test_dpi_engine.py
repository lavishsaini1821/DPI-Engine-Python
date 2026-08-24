from src.dpi_engine import DPIEngine
from src.pcap_reader import PcapReader


# Load the test PCAP file.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Create the DPI Engine.
engine = DPIEngine()

# Process the packets through the DPI pipeline.
parsed_packets, protocol_statistics, decisions, forwarded_packets = engine.process_packets(packets)

print("Total packets:", len(packets))
print("Parsed packets:", len(parsed_packets))

print("\nProtocol Statistics:")

for protocol, count in protocol_statistics.items():
    print(f"{protocol}: {count}")