from scapy.utils import wrpcap
from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine

# Read packets from the input PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Process packets through the DPI engine.
engine = DPIEngine()

(
    parsed_packets,
    protocol_statistics,
    decisions,
    forwarded_packets
) = engine.process_packets(packets)

# Write only FORWARD packets to the output PCAP.
output_file = "output/filtered_output.pcap"

wrpcap(
    output_file,
    forwarded_packets
)

print("Input packets:", len(packets))
print("Forwarded packets:", len(forwarded_packets))
print("Dropped packets:", decisions.count("DROP"))
print("Output PCAP:", output_file)