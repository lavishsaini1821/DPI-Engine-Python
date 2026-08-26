from scapy.all import rdpcap


INPUT_PCAP = "input/test_dpi.pcap"
OUTPUT_PCAP = "output/day18_output.pcap"


print("========== DAY 18 PCAP COMPARISON ==========")


# Read both PCAP files
input_packets = rdpcap(INPUT_PCAP)
output_packets = rdpcap(OUTPUT_PCAP)


print(f"Input packets: {len(input_packets)}")
print(f"Output packets: {len(output_packets)}")


# --------------------------------------------------
# Compare packets using their raw bytes.
# --------------------------------------------------

input_raw = [bytes(packet) for packet in input_packets]
output_raw = [bytes(packet) for packet in output_packets]


# Count how many input packets are preserved
# in the output PCAP.
preserved_count = 0

for packet in input_raw:
    if packet in output_raw:
        preserved_count += 1


# Find packets that exist in input but not output.
removed_packets = []

for packet in input_raw:
    if packet not in output_raw:
        removed_packets.append(packet)


print("\n========== COMPARISON ==========")

print(f"Packets preserved: {preserved_count}")
print(f"Packets removed: {len(removed_packets)}")


# --------------------------------------------------
# Verification
# --------------------------------------------------

preserved_pass = (
    preserved_count == len(output_packets)
)

removed_pass = (
    len(removed_packets) == 1
)

count_pass = (
    len(input_packets) == len(output_packets) + len(removed_packets)
)


print("\n========== VERIFICATION ==========")

if preserved_pass:
    print("Allowed packets preserved: PASS")
else:
    print("Allowed packets preserved: FAIL")


if removed_pass:
    print("Dropped packets removed: PASS")
else:
    print("Dropped packets removed: FAIL")


if count_pass:
    print("Input/output packet relationship: PASS")
else:
    print("Input/output packet relationship: FAIL")


if preserved_pass and removed_pass and count_pass:
    print("\nPCAP comparison: PASS")
else:
    print("\nPCAP comparison: FAIL")


assert preserved_pass
assert removed_pass
assert count_pass