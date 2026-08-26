from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine

# Read packets from the input PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Process packets through the DPI engine.
engine = DPIEngine()

parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets(packets)
)

print("========== DAY 17 TOTAL BYTES VERIFICATION ==========")

print(f"Total packets: {len(parsed_packets)}")
print(f"Total bytes: {engine.analyzer.total_bytes}")

# Verify that packet bytes were actually calculated.
if engine.analyzer.total_bytes > 0:
    print("Total bytes calculation: PASS")
else:
    print("Total bytes calculation: FAIL")

assert engine.analyzer.total_bytes == 5738