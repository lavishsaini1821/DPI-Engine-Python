from collections import Counter
from scapy.utils import rdpcap

INPUT_FILE = "input/test_dpi.pcap"
OUTPUT_FILE = "output/filtered_output.pcap"

# Read both PCAP files.
input_packets = rdpcap(INPUT_FILE)
output_packets = rdpcap(OUTPUT_FILE)

# Convert packets to raw bytes so that we can compare
# the actual packet contents.
input_packet_bytes = Counter(
    bytes(packet) for packet in input_packets
)

output_packet_bytes = Counter(
    bytes(packet) for packet in output_packets
)

print("========== DAY 16 PACKET VERIFICATION ==========")

print(f"Input packets: {len(input_packets)}")
print(f"Output packets: {len(output_packets)}")

# Check whether every packet present in the output
# also existed in the original input.
output_packets_valid = (
    output_packet_bytes - input_packet_bytes
    == Counter()
)

if output_packets_valid:
    print("Allowed packets preserved: PASS")
else:
    print("Allowed packets preserved: FAIL")

# Calculate packets that existed in the input
# but are missing from the filtered output.
dropped_packets = input_packet_bytes - output_packet_bytes

print(f"Packets removed from output: {sum(dropped_packets.values())}")

dropped_pass = sum(dropped_packets.values()) == 1

if dropped_pass:
    print("Dropped packets excluded: PASS")
else:
    print("Dropped packets excluded: FAIL")


assert output_packets_valid
assert dropped_pass
