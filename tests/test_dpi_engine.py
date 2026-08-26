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


# Verify the expected result for input/test_dpi.pcap.
# The decision count is asserted separately from the packet count
# because a broken loop can still parse every packet while
# producing a decision for only some of them.
assert len(parsed_packets) == len(packets)
assert len(decisions) == len(packets)
assert decisions.count("FORWARD") == 76
assert decisions.count("DROP") == 1
assert len(forwarded_packets) == 76
assert protocol_statistics["TCP"] == 73
assert protocol_statistics["UDP"] == 4