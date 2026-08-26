from scapy.utils import rdpcap


INPUT_FILE = "input/test_dpi.pcap"
OUTPUT_FILE = "output/filtered_output.pcap"


# Read the original input PCAP.
input_packets = rdpcap(INPUT_FILE)

# Read the filtered output PCAP.
output_packets = rdpcap(OUTPUT_FILE)


input_count = len(input_packets)
output_count = len(output_packets)

dropped_count = input_count - output_count


print("========== DAY 16 PCAP VERIFICATION ==========")

print(f"Input PCAP packets: {input_count}")
print(f"Output PCAP packets: {output_count}")
print(f"Dropped packets: {dropped_count}")


# Verify that the output contains fewer packets than
# the original because at least one packet was dropped.
filtering_pass = output_count < input_count

if filtering_pass:
    print("Output filtering: PASS")
else:
    print("Output filtering: FAIL")


# Verify the expected V1 result.
count_pass = output_count == 76 and dropped_count == 1

if count_pass:
    print("Packet count verification: PASS")
else:
    print("Packet count verification: FAIL")


assert filtering_pass
assert count_pass